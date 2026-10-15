// SPDX-License-Identifier: LGPL-2.1-or-later
//! The file commands: CREATE (MS-SMB2 2.2.13, 2.2.14), CLOSE (2.2.15,
//! 2.2.16), FLUSH (2.2.17, 2.2.18), READ (2.2.19, 2.2.20), WRITE (2.2.21,
//! 2.2.22), IOCTL (2.2.31, 2.2.32), QUERY_DIRECTORY (2.2.33, 2.2.34) with
//! FileIdBothDirectoryInformation (MS-FSCC 2.4.17), QUERY_INFO (2.2.37,
//! 2.2.38) with FileFsFullSizeInformation (MS-FSCC 2.5.4), and SET_INFO
//! (2.2.39, 2.2.40) with FileBasicInformation, FileRenameInformation and
//! FileDispositionInformation (MS-FSCC 2.4.7, 2.4.37.2, 2.4.11).

use super::body_reader;
use crate::error::{Result, protocol};
use crate::names::{units_of, utf16le};
use crate::wire::{Reader, Writer, from_u32, slice_at, to_u16, to_u32};

/// A 16-byte SMB2 file id (persistent ‖ volatile).
pub type FileId = [u8; 16];
/// The file id of a related compound request: "the file of the previous
/// request" (MS-SMB2 3.2.4.1.4).
pub const RELATED_FILE_ID: FileId = [0xFF; 16];

/// Access mask bits (MS-SMB2 2.2.13.1).
pub mod access {
    /// FILE_READ_DATA / FILE_LIST_DIRECTORY.
    pub const READ_DATA: u32 = 0x0000_0001;
    /// FILE_WRITE_DATA / FILE_ADD_FILE.
    pub const WRITE_DATA: u32 = 0x0000_0002;
    /// FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY.
    pub const APPEND_DATA: u32 = 0x0000_0004;
    /// FILE_READ_ATTRIBUTES.
    pub const READ_ATTRIBUTES: u32 = 0x0000_0080;
    /// FILE_WRITE_ATTRIBUTES.
    pub const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    /// DELETE.
    pub const DELETE: u32 = 0x0001_0000;
    /// SYNCHRONIZE.
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
}

/// CreateDisposition values.
pub mod disposition {
    /// FILE_OPEN: open an existing file.
    pub const OPEN: u32 = 1;
    /// FILE_CREATE: fail if it exists.
    pub const CREATE: u32 = 2;
    /// FILE_OVERWRITE_IF: create or truncate.
    pub const OVERWRITE_IF: u32 = 5;
}

/// CreateOptions bits.
pub mod options {
    /// FILE_DIRECTORY_FILE: the object must be a folder.
    pub const DIRECTORY: u32 = 0x0000_0001;
    /// FILE_NON_DIRECTORY_FILE: the object must not be a folder.
    pub const NON_DIRECTORY: u32 = 0x0000_0040;
}

/// FileAttributes bits (MS-FSCC 2.6).
pub mod attributes {
    /// FILE_ATTRIBUTE_READONLY.
    pub const READONLY: u32 = 0x0000_0001;
    /// FILE_ATTRIBUTE_HIDDEN.
    pub const HIDDEN: u32 = 0x0000_0002;
    /// FILE_ATTRIBUTE_SYSTEM.
    pub const SYSTEM: u32 = 0x0000_0004;
    /// FILE_ATTRIBUTE_DIRECTORY.
    pub const DIRECTORY: u32 = 0x0000_0010;
    /// FILE_ATTRIBUTE_NORMAL.
    pub const NORMAL: u32 = 0x0000_0080;
    /// FILE_ATTRIBUTE_REPARSE_POINT.
    pub const REPARSE_POINT: u32 = 0x0000_0400;
}

/// FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE.
pub const SHARE_ALL: u32 = 0x7;
/// FSCTL_PIPE_TRANSCEIVE (MS-FSCC 2.3.49).
pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
/// The longest path accepted in a CREATE or rename, in UTF-16 units
/// (MAX_PATH-sized names are far shorter; the field is 16 bits of bytes).
pub const MAX_PATH_UNITS: usize = 32_767;
/// Names in directory entries are at most this long (bytes of UTF-16):
/// 255 units with headroom.
pub const MAX_NAME_BYTES: usize = 1024;
/// QUERY_DIRECTORY entries accepted per response.
pub const MAX_ENTRIES: usize = 4096;

/// The four FILETIME stamps of a file (100 ns since 1601; 0: none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Times {
    /// CreationTime.
    pub creation: u64,
    /// LastAccessTime.
    pub last_access: u64,
    /// LastWriteTime.
    pub last_write: u64,
    /// ChangeTime.
    pub change: u64,
}

impl Times {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self { creation: r.u64()?, last_access: r.u64()?, last_write: r.u64()?, change: r.u64()? })
    }
}

/// FILETIME of the Unix epoch.
const EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
/// FILETIME units per millisecond.
const PER_MS: u64 = 10_000;

/// Milliseconds since the Unix epoch of a FILETIME; `None` for 0 (no time)
/// and for times before 1970.
#[must_use]
pub fn ms_of_filetime(ft: u64) -> Option<i64> {
    // 0 (no time) is before the epoch as well.
    i64::try_from(ft.checked_sub(EPOCH_FILETIME)? / PER_MS).ok()
}

/// The FILETIME of a time in ms since the Unix epoch; `None` before 1970.
#[must_use]
pub fn filetime_of_ms(ms: i64) -> Option<u64> {
    u64::try_from(ms).ok()?.checked_mul(PER_MS)?.checked_add(EPOCH_FILETIME)
}

/// A CREATE request: no oplock, no lease, no create contexts.
#[derive(Debug, Clone, Copy)]
pub struct Create<'a> {
    /// The path from the share root, `\`-separated, UTF-16.
    pub name: &'a [u16],
    /// DesiredAccess.
    pub access: u32,
    /// FileAttributes of a new file.
    pub attributes: u32,
    /// CreateDisposition.
    pub disposition: u32,
    /// CreateOptions.
    pub options: u32,
}

impl Create<'_> {
    /// The request body.
    ///
    /// # Errors
    /// A name longer than [`MAX_PATH_UNITS`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.name.len() > MAX_PATH_UNITS {
            return Err(protocol("the path is too long"));
        }
        let name = utf16le(self.name);
        let mut w = Writer::new();
        w.u16(57)
            .u8(0) // SecurityFlags
            .u8(0) // RequestedOplockLevel: none
            .u32(2) // ImpersonationLevel: Impersonation
            .u64(0) // SmbCreateFlags
            .u64(0) // Reserved
            .u32(self.access)
            .u32(self.attributes)
            .u32(SHARE_ALL)
            .u32(self.disposition)
            .u32(self.options)
            .u16(120) // NameOffset: header + 56
            .u16(to_u16(name.len())?)
            .u32(0) // CreateContextsOffset
            .u32(0); // CreateContextsLength
        if name.is_empty() {
            w.u8(0); // the Buffer holds at least one byte
        } else {
            w.bytes(&name);
        }
        Ok(w.into_vec())
    }
}

/// The parts of a CREATE response used here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Created {
    /// The times.
    pub times: Times,
    /// EndofFile.
    pub end_of_file: u64,
    /// FileAttributes.
    pub attributes: u32,
    /// FileId.
    pub file_id: FileId,
}

impl Created {
    /// Decodes a CREATE response.
    ///
    /// # Errors
    /// A malformed body or create contexts outside the message.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let mut r = body_reader(msg, 89, "CREATE response")?;
        r.skip(6)?; // OplockLevel, Flags, CreateAction
        let times = Times::read(&mut r)?;
        r.skip(8)?; // AllocationSize
        let end_of_file = r.u64()?;
        let attributes = r.u32()?;
        r.skip(4)?;
        let file_id = r.array()?;
        let ctx_offset = from_u32(r.u32()?)?;
        let ctx_len = from_u32(r.u32()?)?;
        if ctx_len > 0 {
            slice_at(msg, ctx_offset, ctx_len)?;
        }
        Ok(Self { times, end_of_file, attributes, file_id })
    }
}

/// CLOSE request body.
#[must_use]
pub fn close_request(file_id: &FileId) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(24).u16(0).u32(0).bytes(file_id);
    w.into_vec()
}

/// Checks a CLOSE response.
///
/// # Errors
/// Another StructureSize or a short body.
pub fn check_close_response(msg: &[u8]) -> Result<()> {
    body_reader(msg, 60, "CLOSE response")?.skip(58)
}

/// FLUSH request body.
#[must_use]
pub fn flush_request(file_id: &FileId) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(24).u16(0).u32(0).bytes(file_id);
    w.into_vec()
}

/// Checks a FLUSH response (StructureSize 4).
///
/// # Errors
/// Another StructureSize or a short body.
pub fn check_flush_response(msg: &[u8]) -> Result<()> {
    body_reader(msg, 4, "FLUSH response")?.skip(2)
}

/// READ request body.
///
/// # Errors
/// A length above 32 bits.
pub fn read_request(file_id: &FileId, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(49)
        .u8(0x50) // Padding: the data right after the 16-byte response body
        .u8(0) // Flags
        .u32(to_u32(length)?)
        .u64(offset)
        .bytes(file_id)
        .u32(0) // MinimumCount
        .u32(0) // Channel
        .u32(0) // RemainingBytes
        .u16(0) // ReadChannelInfoOffset
        .u16(0) // ReadChannelInfoLength
        .u8(0); // Buffer
    Ok(w.into_vec())
}

/// The data of a READ response; refuses more than `requested` bytes.
///
/// # Errors
/// A malformed body, data outside the message or longer than requested.
pub fn read_response(msg: &[u8], requested: usize) -> Result<&[u8]> {
    let mut r = body_reader(msg, 17, "READ response")?;
    let offset = usize::from(r.u8()?);
    r.skip(1)?;
    let len = from_u32(r.u32()?)?;
    if len > requested {
        return Err(protocol(format!("READ returned {len} bytes for {requested} requested")));
    }
    if len == 0 {
        return Ok(&[]);
    }
    if offset < 80 {
        return Err(protocol("READ DataOffset inside the header"));
    }
    slice_at(msg, offset, len)
}

/// WRITE request body with `data` (DataOffset right after the 48 fixed
/// bytes).
///
/// # Errors
/// More data than 32 bits can count.
pub fn write_request(file_id: &FileId, offset: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(49)
        .u16(112) // DataOffset: header + 48
        .u32(to_u32(data.len())?)
        .u64(offset)
        .bytes(file_id)
        .u32(0) // Channel
        .u32(0) // RemainingBytes
        .u16(0) // WriteChannelInfoOffset
        .u16(0) // WriteChannelInfoLength
        .u32(0) // Flags
        .bytes(data);
    Ok(w.into_vec())
}

/// The Count of a WRITE response; refuses more than `sent`.
///
/// # Errors
/// A malformed body or a count above what was sent.
pub fn write_response(msg: &[u8], sent: usize) -> Result<usize> {
    let mut r = body_reader(msg, 17, "WRITE response")?;
    r.skip(2)?;
    let count = from_u32(r.u32()?)?;
    r.skip(8)?; // Remaining, WriteChannelInfoOffset/Length
    if count > sent {
        return Err(protocol(format!("WRITE wrote {count} bytes of {sent}")));
    }
    Ok(count)
}

/// IOCTL request: an FSCTL with `input`, answering at most `max_output`.
///
/// # Errors
/// Sizes above 32 bits.
pub fn ioctl_request(ctl_code: u32, file_id: &FileId, input: &[u8], max_output: usize) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(57)
        .u16(0)
        .u32(ctl_code)
        .bytes(file_id)
        .u32(120) // InputOffset: header + 56
        .u32(to_u32(input.len())?)
        .u32(0) // MaxInputResponse
        .u32(0) // OutputOffset
        .u32(0) // OutputCount
        .u32(to_u32(max_output)?)
        .u32(1) // Flags: SMB2_0_IOCTL_IS_FSCTL
        .u32(0)
        .bytes(input);
    Ok(w.into_vec())
}

/// The output of an IOCTL response; refuses more than `max_output`.
///
/// # Errors
/// A malformed body, output outside the message or above the maximum.
pub fn ioctl_response(msg: &[u8], max_output: usize) -> Result<&[u8]> {
    let mut r = body_reader(msg, 49, "IOCTL response")?;
    r.skip(2 + 4 + 16 + 8)?; // Reserved, CtlCode, FileId, InputOffset/Count
    let offset = from_u32(r.u32()?)?;
    let len = from_u32(r.u32()?)?;
    if len > max_output {
        return Err(protocol("IOCTL returned more than requested"));
    }
    if len == 0 {
        return Ok(&[]);
    }
    slice_at(msg, offset, len)
}

/// QUERY_DIRECTORY request body (FileIdBothDirectoryInformation, `*`).
///
/// # Errors
/// An output length above 32 bits.
pub fn query_directory_request(file_id: &FileId, restart: bool, out_len: usize) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(33)
        .u8(0x25) // FileIdBothDirectoryInformation
        .u8(u8::from(restart)) // SMB2_RESTART_SCANS
        .u32(0) // FileIndex
        .bytes(file_id)
        .u16(96) // FileNameOffset: header + 32
        .u16(2) // FileNameLength: "*"
        .u32(to_u32(out_len)?)
        .bytes(&[b'*', 0]);
    Ok(w.into_vec())
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The name, UTF-16.
    pub name: Vec<u16>,
    /// The times.
    pub times: Times,
    /// EndOfFile.
    pub size: u64,
    /// FileAttributes.
    pub attributes: u32,
}

/// The entries of a QUERY_DIRECTORY response; `max_out` is the
/// OutputBufferLength asked for.
///
/// # Errors
/// A malformed body or entries: see [`parse_id_both_directory`].
pub fn query_directory_response(msg: &[u8], max_out: usize) -> Result<Vec<DirEntry>> {
    let mut r = body_reader(msg, 9, "QUERY_DIRECTORY response")?;
    let offset = usize::from(r.u16()?);
    let len = from_u32(r.u32()?)?;
    if len > max_out {
        return Err(protocol("QUERY_DIRECTORY returned more than requested"));
    }
    parse_id_both_directory(slice_at(msg, offset, len)?)
}

/// Parses FileIdBothDirectoryInformation entries (MS-FSCC 2.4.17).
///
/// # Errors
/// An entry or name outside the buffer, an odd or too long name, an
/// unaligned NextEntryOffset or one that does not move past the entry, more
/// than [`MAX_ENTRIES`] entries.
pub fn parse_id_both_directory(buf: &[u8]) -> Result<Vec<DirEntry>> {
    const FIXED: usize = 104;
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        if out.len() == MAX_ENTRIES {
            return Err(protocol("too many directory entries"));
        }
        let entry = buf.get(pos..).ok_or_else(|| protocol("entry offset outside the buffer"))?;
        let mut r = Reader::new(entry);
        let next = from_u32(r.u32()?)?;
        r.skip(4)?; // FileIndex
        let times = Times::read(&mut r)?;
        let size = r.u64()?;
        r.skip(8)?; // AllocationSize
        let attributes = r.u32()?;
        let name_len = from_u32(r.u32()?)?;
        if name_len > MAX_NAME_BYTES {
            return Err(protocol("directory entry name too long"));
        }
        r.seek(FIXED)?;
        let name = units_of(r.bytes(name_len)?).ok_or_else(|| protocol("odd name length"))?;
        out.push(DirEntry { name, times, size, attributes });
        if next == 0 {
            return Ok(out);
        }
        if !next.is_multiple_of(8) || next < FIXED.saturating_add(name_len) {
            return Err(protocol("bad NextEntryOffset"));
        }
        pos = pos.checked_add(next).ok_or_else(|| protocol("NextEntryOffset overflow"))?;
    }
}

/// QUERY_INFO request body for a file system information class.
///
/// # Errors
/// An output length above 32 bits.
pub fn query_fs_info_request(file_id: &FileId, class: u8, out_len: usize) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(41)
        .u8(2) // InfoType: SMB2_0_INFO_FILESYSTEM
        .u8(class)
        .u32(to_u32(out_len)?)
        .u16(0) // InputBufferOffset
        .u16(0)
        .u32(0) // InputBufferLength
        .u32(0) // AdditionalInformation
        .u32(0) // Flags
        .bytes(file_id);
    Ok(w.into_vec())
}

/// FileFsFullSizeInformation.
pub const FS_FULL_SIZE_INFORMATION: u8 = 7;

/// FileFsFullSizeInformation (MS-FSCC 2.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsFullSize {
    /// TotalAllocationUnits.
    pub total_units: u64,
    /// CallerAvailableAllocationUnits.
    pub caller_available_units: u64,
    /// SectorsPerAllocationUnit × BytesPerSector.
    pub unit_bytes: u64,
}

/// FileFsFullSizeInformation of a QUERY_INFO response.
///
/// # Errors
/// A malformed body or buffer.
pub fn fs_full_size_response(msg: &[u8]) -> Result<FsFullSize> {
    let mut r = body_reader(msg, 9, "QUERY_INFO response")?;
    let offset = usize::from(r.u16()?);
    let len = from_u32(r.u32()?)?;
    if len < 32 {
        return Err(protocol("FileFsFullSizeInformation too short"));
    }
    let mut b = Reader::new(slice_at(msg, offset, len)?);
    let total_units = b.u64()?;
    let caller_available_units = b.u64()?;
    b.skip(8)?; // ActualAvailableAllocationUnits
    let sectors = u64::from(b.u32()?);
    let bytes = u64::from(b.u32()?);
    Ok(FsFullSize { total_units, caller_available_units, unit_bytes: sectors.saturating_mul(bytes) })
}

/// SET_INFO request body: `buffer` for a file information class.
///
/// # Errors
/// A buffer above 32 bits.
pub fn set_info_request(file_id: &FileId, class: u8, buffer: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(33)
        .u8(1) // InfoType: SMB2_0_INFO_FILE
        .u8(class)
        .u32(to_u32(buffer.len())?)
        .u16(96) // BufferOffset: header + 32
        .u16(0)
        .u32(0) // AdditionalInformation
        .bytes(file_id)
        .bytes(buffer);
    Ok(w.into_vec())
}

/// Checks a SET_INFO response (StructureSize 2).
///
/// # Errors
/// Another StructureSize.
pub fn check_set_info_response(msg: &[u8]) -> Result<()> {
    body_reader(msg, 2, "SET_INFO response").map(|_| ())
}

/// FileBasicInformation.
pub const BASIC_INFORMATION: u8 = 4;
/// FileRenameInformation.
pub const RENAME_INFORMATION: u8 = 10;
/// FileDispositionInformation.
pub const DISPOSITION_INFORMATION: u8 = 13;

/// FileBasicInformation that sets the last write and last access times
/// given and leaves everything else (0: unchanged).
#[must_use]
pub fn basic_information(last_write: Option<u64>, last_access: Option<u64>) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(0) // CreationTime
        .u64(last_access.unwrap_or(0))
        .u64(last_write.unwrap_or(0))
        .u64(0) // ChangeTime
        .u32(0) // FileAttributes: unchanged
        .u32(0);
    w.into_vec()
}

/// FileRenameInformation (the SMB2 form): the new path from the share root.
///
/// # Errors
/// A path longer than [`MAX_PATH_UNITS`].
pub fn rename_information(target: &[u16], replace: bool) -> Result<Vec<u8>> {
    if target.len() > MAX_PATH_UNITS {
        return Err(protocol("the path is too long"));
    }
    let name = utf16le(target);
    let mut w = Writer::new();
    w.u8(u8::from(replace)).bytes(&[0; 7]).u64(0).u32(to_u32(name.len())?).bytes(&name);
    Ok(w.into_vec())
}

/// FileDispositionInformation with DeletePending set.
#[must_use]
pub fn delete_on_close() -> Vec<u8> {
    vec![1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{Command, Header, build, flags};

    fn resp(cmd: Command, body: &[u8]) -> Vec<u8> {
        let mut h = Header::request(cmd, 1, 1, 1);
        h.flags = flags::SERVER_TO_REDIR;
        build(&h, body)
    }

    fn u(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    pub(crate) fn entry(name: &str, size: u64, attributes: u32, next: u32) -> Vec<u8> {
        let n = utf16le(&u(name));
        let mut w = Writer::new();
        w.u32(next).u32(0).u64(1).u64(2).u64(3).u64(4).u64(size).u64(0).u32(attributes);
        w.u32(u32::try_from(n.len()).unwrap());
        w.u32(0).u8(0).u8(0).bytes(&[0; 24]).u16(0).u64(0).bytes(&n);
        w.into_vec()
    }

    #[test]
    fn filetimes() {
        assert_eq!(ms_of_filetime(0), None);
        assert_eq!(ms_of_filetime(EPOCH_FILETIME - 1), None);
        assert_eq!(ms_of_filetime(EPOCH_FILETIME), Some(0));
        assert_eq!(ms_of_filetime(EPOCH_FILETIME + 15_000), Some(1));
        assert_eq!(ms_of_filetime(u64::MAX), Some(1_833_029_933_770_955));
        assert_eq!(filetime_of_ms(0), Some(EPOCH_FILETIME));
        assert_eq!(filetime_of_ms(1_700_000_000_123), Some(EPOCH_FILETIME + 17_000_000_001_230_000));
        assert_eq!(filetime_of_ms(-1), None);
        assert_eq!(filetime_of_ms(i64::MAX), None);
        assert_eq!(ms_of_filetime(filetime_of_ms(1_234_567).unwrap()), Some(1_234_567));
    }

    #[test]
    fn create_request_layout() {
        let name = u("dir\\file.txt");
        let c = Create {
            name: &name,
            access: access::READ_DATA,
            attributes: attributes::NORMAL,
            disposition: disposition::OPEN,
            options: options::NON_DIRECTORY,
        };
        let b = c.encode().unwrap();
        assert_eq!(&b[..8], &[57, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(u32::from_le_bytes(b[24..28].try_into().unwrap()), access::READ_DATA);
        assert_eq!(u32::from_le_bytes(b[28..32].try_into().unwrap()), attributes::NORMAL);
        assert_eq!(u32::from_le_bytes(b[32..36].try_into().unwrap()), SHARE_ALL);
        assert_eq!(u32::from_le_bytes(b[36..40].try_into().unwrap()), disposition::OPEN);
        assert_eq!(u32::from_le_bytes(b[40..44].try_into().unwrap()), options::NON_DIRECTORY);
        assert_eq!(&b[44..48], &[120, 0, 24, 0]);
        assert_eq!(&b[48..56], &[0; 8]);
        assert_eq!(&b[56..], &utf16le(&name)[..]);
        let root = Create { name: &[], ..c }.encode().unwrap();
        assert_eq!(root.len(), 57);
        assert_eq!(&root[44..48], &[120, 0, 0, 0]);
        let long = vec![0x61u16; MAX_PATH_UNITS + 1];
        Create { name: &long, ..c }.encode().unwrap_err();
        let max = vec![0x61u16; MAX_PATH_UNITS];
        Create { name: &max, ..c }.encode().unwrap();
    }

    #[test]
    fn create_response_decode() {
        let body = |ctx_offset: u32, ctx_len: u32| {
            let mut w = Writer::new();
            w.u16(89).u8(0).u8(0).u32(1).u64(11).u64(12).u64(13).u64(14).u64(4096).u64(1234).u32(0x20).u32(0);
            w.bytes(&[0xAB; 16]).u32(ctx_offset).u32(ctx_len);
            w.into_vec()
        };
        let r = Created::decode(&resp(Command::Create, &body(0, 0))).unwrap();
        assert_eq!(r.times, Times { creation: 11, last_access: 12, last_write: 13, change: 14 });
        assert_eq!((r.end_of_file, r.attributes, r.file_id), (1234, 0x20, [0xAB; 16]));
        Created::decode(&resp(Command::Create, &body(152, 400))).unwrap_err();
        // No contexts: the offset does not matter.
        Created::decode(&resp(Command::Create, &body(0xffff, 0))).unwrap();
        let mut with_ctx = resp(Command::Create, &body(152, 4));
        with_ctx.extend_from_slice(&[0; 4]);
        Created::decode(&with_ctx).unwrap();
        Created::decode(&resp(Command::Create, &body(0, 0)[..80])).unwrap_err();
    }

    #[test]
    fn close_and_flush() {
        let id = [7u8; 16];
        let c = close_request(&id);
        assert_eq!(&c[..8], &[24, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&c[8..], &id);
        assert_eq!(flush_request(&id), c);
        let mut body = vec![60, 0];
        body.extend_from_slice(&[0; 58]);
        check_close_response(&resp(Command::Close, &body)).unwrap();
        check_close_response(&resp(Command::Close, &body[..59])).unwrap_err();
        check_flush_response(&resp(Command::Flush, &[4, 0, 0, 0])).unwrap();
        check_flush_response(&resp(Command::Flush, &[4, 0, 0])).unwrap_err();
        check_flush_response(&resp(Command::Flush, &[2, 0, 0, 0])).unwrap_err();
    }

    #[test]
    fn read_request_and_response() {
        let r = read_request(&[1; 16], 0x0102_0304_0506_0708, 65_536).unwrap();
        assert_eq!(r.len(), 49);
        assert_eq!(&r[..4], &[49, 0, 0x50, 0]);
        assert_eq!(&r[4..8], &65_536u32.to_le_bytes());
        assert_eq!(&r[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&r[16..32], &[1; 16]);
        assert_eq!(&r[32..], &[0; 17]);
        let mut body = vec![17, 0, 80, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(b"hello");
        let msg = resp(Command::Read, &body);
        assert_eq!(read_response(&msg, 5).unwrap(), b"hello");
        assert_eq!(read_response(&msg, 6).unwrap(), b"hello");
        read_response(&msg, 4).unwrap_err();
        let mut short = msg.clone();
        short.pop();
        read_response(&short, 5).unwrap_err();
        let mut inside = msg.clone();
        inside[66] = 79;
        read_response(&inside, 5).unwrap_err();
        let mut empty = msg;
        empty[68] = 0;
        empty[66] = 0;
        assert_eq!(read_response(&empty, 5).unwrap(), b"");
    }

    #[test]
    fn write_request_and_response() {
        let w = write_request(&[2; 16], 9, b"abc").unwrap();
        assert_eq!(&w[..8], &[49, 0, 112, 0, 3, 0, 0, 0]);
        assert_eq!(&w[8..16], &9u64.to_le_bytes());
        assert_eq!(&w[16..32], &[2; 16]);
        assert_eq!(&w[32..48], &[0; 16]);
        assert_eq!(&w[48..], b"abc");
        let body = [17, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(write_response(&resp(Command::Write, &body), 3).unwrap(), 3);
        assert_eq!(write_response(&resp(Command::Write, &body), 4).unwrap(), 3);
        write_response(&resp(Command::Write, &body), 2).unwrap_err();
        write_response(&resp(Command::Write, &body[..15]), 3).unwrap_err();
    }

    #[test]
    fn ioctl_request_and_response() {
        let r = ioctl_request(FSCTL_PIPE_TRANSCEIVE, &[3; 16], b"in", 4280).unwrap();
        assert_eq!(&r[..8], &[57, 0, 0, 0, 0x17, 0xC0, 0x11, 0]);
        assert_eq!(&r[8..24], &[3; 16]);
        assert_eq!(&r[24..32], &[120, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&r[32..44], &[0; 12]);
        assert_eq!(&r[44..48], &4280u32.to_le_bytes());
        assert_eq!(&r[48..56], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&r[56..], b"in");
        let mut w = Writer::new();
        w.u16(49)
            .u16(0)
            .u32(FSCTL_PIPE_TRANSCEIVE)
            .bytes(&[3; 16])
            .u32(0)
            .u32(0)
            .u32(112)
            .u32(3)
            .u32(0)
            .u32(0);
        w.bytes(b"out");
        let msg = resp(Command::Ioctl, &w.into_vec());
        assert_eq!(ioctl_response(&msg, 3).unwrap(), b"out");
        ioctl_response(&msg, 2).unwrap_err();
        ioctl_response(&msg[..msg.len() - 1], 3).unwrap_err();
        let mut none = msg;
        none[64 + 36] = 0;
        assert_eq!(ioctl_response(&none, 3).unwrap(), b"");
    }

    #[test]
    fn query_directory_request_layout() {
        let q = query_directory_request(&[4; 16], true, 65_536).unwrap();
        assert_eq!(&q[..8], &[33, 0, 0x25, 1, 0, 0, 0, 0]);
        assert_eq!(&q[8..24], &[4; 16]);
        assert_eq!(&q[24..28], &[96, 0, 2, 0]);
        assert_eq!(&q[28..32], &65_536u32.to_le_bytes());
        assert_eq!(&q[32..], &[b'*', 0]);
        assert_eq!(query_directory_request(&[4; 16], false, 1).unwrap()[3], 0);
    }

    #[test]
    fn directory_entries() {
        let a = entry("a.txt", 3, 0x20, 0);
        let pad = a.len().next_multiple_of(8);
        let mut two = entry("a.txt", 3, 0x20, u32::try_from(pad).unwrap());
        two.resize(pad, 0);
        two.extend_from_slice(&entry("\u{dc}n\u{ef}", 7, 0x10, 0));
        let got = parse_id_both_directory(&two).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, u("a.txt"));
        assert_eq!(got[0].times, Times { creation: 1, last_access: 2, last_write: 3, change: 4 });
        assert_eq!((got[1].name.clone(), got[1].size, got[1].attributes), (u("\u{dc}n\u{ef}"), 7, 0x10));

        // NextEntryOffset pointing back into the entry, unaligned, or past the end.
        parse_id_both_directory(&entry("x", 1, 0, 8)).unwrap_err();
        parse_id_both_directory(&entry("x", 1, 0, 107)).unwrap_err();
        parse_id_both_directory(&entry("x", 1, 0, 4096)).unwrap_err();
        // Unaligned, though past the entry and with an entry there.
        let mut unaligned = entry("x", 1, 0, 108);
        unaligned.resize(108, 0);
        unaligned.extend_from_slice(&entry("y", 1, 0, 0));
        parse_id_both_directory(&unaligned).unwrap_err();
        // The smallest forward offset (fixed part and name, aligned) is fine.
        let mut tight = entry("xyzw", 1, 0, 112);
        tight.extend_from_slice(&entry("y", 1, 0, 0));
        assert_eq!(parse_id_both_directory(&tight).unwrap().len(), 2);
        // A name beyond the buffer, odd, or above the cap.
        let mut long = entry("x", 1, 0, 0);
        long[60..64].copy_from_slice(&100u32.to_le_bytes());
        parse_id_both_directory(&long).unwrap_err();
        long[60..64].copy_from_slice(&1u32.to_le_bytes());
        parse_id_both_directory(&long).unwrap_err();
        let mut capped = entry(&"n".repeat(513), 1, 0, 0);
        parse_id_both_directory(&capped).unwrap_err();
        capped = entry(&"n".repeat(512), 1, 0, 0);
        parse_id_both_directory(&capped).unwrap();
        parse_id_both_directory(&[]).unwrap_err();
    }

    #[test]
    fn too_many_entries() {
        let mut one = entry("e", 0, 0, 112);
        one.resize(112, 0);
        let mut many = one.repeat(MAX_ENTRIES);
        many.extend_from_slice(&entry("e", 0, 0, 0));
        parse_id_both_directory(&many).unwrap_err();
        let mut max = one.repeat(MAX_ENTRIES - 1);
        max.extend_from_slice(&entry("e", 0, 0, 0));
        assert_eq!(parse_id_both_directory(&max).unwrap().len(), MAX_ENTRIES);
    }

    #[test]
    fn query_directory_response_bounds() {
        let e = entry("a", 1, 0, 0);
        let mut body = vec![9, 0, 72, 0];
        body.extend_from_slice(&u32::try_from(e.len()).unwrap().to_le_bytes());
        body.extend_from_slice(&e);
        let msg = resp(Command::QueryDirectory, &body);
        assert_eq!(query_directory_response(&msg, 65_536).unwrap().len(), 1);
        assert_eq!(query_directory_response(&msg, e.len()).unwrap().len(), 1);
        query_directory_response(&msg, e.len() - 1).unwrap_err();
        let mut bad = msg;
        bad[68..72].copy_from_slice(&9999u32.to_le_bytes());
        query_directory_response(&bad, 65_536).unwrap_err();
    }

    #[test]
    fn fs_full_size() {
        let q = query_fs_info_request(&[5; 16], FS_FULL_SIZE_INFORMATION, 32).unwrap();
        assert_eq!(&q[..8], &[41, 0, 2, 7, 32, 0, 0, 0]);
        assert_eq!(&q[8..24], &[0; 16]);
        assert_eq!(&q[24..], &[5; 16]);
        let mut body = vec![9, 0, 72, 0, 32, 0, 0, 0];
        let mut w = Writer::new();
        w.u64(1000).u64(250).u64(300).u32(8).u32(512);
        body.extend_from_slice(&w.into_vec());
        let msg = resp(Command::QueryInfo, &body);
        assert_eq!(
            fs_full_size_response(&msg).unwrap(),
            FsFullSize { total_units: 1000, caller_available_units: 250, unit_bytes: 4096 }
        );
        let mut short = msg.clone();
        short[68] = 31;
        fs_full_size_response(&short).unwrap_err();
        // More than the structure: the rest is ignored.
        let mut long = msg.clone();
        long[68] = 40;
        long.extend_from_slice(&[0; 8]);
        assert_eq!(fs_full_size_response(&long).unwrap().total_units, 1000);
        fs_full_size_response(&msg[..msg.len() - 1]).unwrap_err();
    }

    #[test]
    fn set_info_buffers() {
        let s = set_info_request(&[6; 16], RENAME_INFORMATION, b"xyz").unwrap();
        assert_eq!(&s[..8], &[33, 0, 1, 10, 3, 0, 0, 0]);
        assert_eq!(&s[8..16], &[96, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&s[16..32], &[6; 16]);
        assert_eq!(&s[32..], b"xyz");
        check_set_info_response(&resp(Command::SetInfo, &[2, 0])).unwrap();
        check_set_info_response(&resp(Command::SetInfo, &[4, 0])).unwrap_err();
        let b = basic_information(Some(5), None);
        assert_eq!(b.len(), 40);
        assert_eq!(&b[..8], &[0; 8]);
        assert_eq!(&b[8..16], &[0; 8]);
        assert_eq!(&b[16..24], &5u64.to_le_bytes());
        assert_eq!(&b[24..40], &[0; 16]);
        assert_eq!(&basic_information(None, Some(6))[8..16], &6u64.to_le_bytes());
        let r = rename_information(&u("a\\b"), true).unwrap();
        assert_eq!(&r[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&r[8..20], &[0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0]);
        assert_eq!(&r[20..], &utf16le(&u("a\\b"))[..]);
        assert_eq!(rename_information(&u("a"), false).unwrap()[0], 0);
        rename_information(&vec![0x61; MAX_PATH_UNITS + 1], false).unwrap_err();
        rename_information(&vec![0x61; MAX_PATH_UNITS], false).unwrap();
        assert_eq!(delete_on_close(), [1]);
        assert_eq!((BASIC_INFORMATION, DISPOSITION_INFORMATION), (4, 13));
    }
}
