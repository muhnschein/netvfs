// SPDX-License-Identifier: LGPL-2.1-or-later
//! Access levels: what the user lets an app do in one account (`access` of a location's info), and what each level allows before a call reaches the server.
//!
//! Add levels (`read-add`, `add`) never change or remove what others put there. What the app added itself stays its own until it renames or removes it (the bridge: for a day): an upload to a temporary name can be finished, resumed, renamed into place or cleaned up.

use crate::errors::ErrorName;
use crate::wire::entry_kind;

/// The location info key of the level.
pub const KEY: &str = "access";

/// What an app may do in one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Level {
    /// `full`: anything.
    Full,
    /// `read-add`: read everything, add new items.
    ReadAdd,
    /// `read`: read everything.
    Read,
    /// `add`: see folders, add new items.
    Add,
}

impl Level {
    /// The stored and wire word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::ReadAdd => "read-add",
            Self::Read => "read",
            Self::Add => "add",
        }
    }

    /// The level of a word.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "full" => Some(Self::Full),
            "read-add" => Some(Self::ReadAdd),
            "read" => Some(Self::Read),
            "add" => Some(Self::Add),
            _ => None,
        }
    }

    /// Reads what others put there.
    #[must_use]
    pub const fn reads(self) -> bool {
        !matches!(self, Self::Add)
    }

    /// Adds new items.
    #[must_use]
    pub const fn adds(self) -> bool {
        !matches!(self, Self::Read)
    }

    /// Changes or removes what others put there.
    #[must_use]
    pub const fn changes(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Allows all that `other` allows.
    #[must_use]
    pub const fn covers(self, other: Self) -> bool {
        (self.reads() || !other.reads())
            && (self.adds() || !other.adds())
            && (self.changes() || !other.changes())
    }
}

/// What a call does to a location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `SpaceInfo`, `Capabilities`, `Disconnect`.
    Info,
    /// `List`, `Walk`.
    Browse,
    /// `Stat`.
    Look,
    /// `ReadLink`.
    ReadLink,
    /// `OpenRead`, `Download`, `Checksum`, a copy's source.
    Read,
    /// `MakeDir`.
    MakeDir,
    /// `Upload` of a new file, a copy's destination without replace.
    Create,
    /// `Upload` that truncates or resumes.
    Rewrite,
    /// `Rename` without replace.
    Rename,
    /// `RemoveFile`, `RemoveDir`.
    Remove,
    /// `SetAttributes`.
    SetAttributes,
    /// `RemoveTree`, `MakeSymlink`, `MakeHardlink`, anything that replaces.
    Unrestricted,
}

/// Whether the item is the app's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Own {
    /// No.
    No,
    /// Added, not completely written yet.
    Writing,
    /// Added and written.
    Written,
}

/// The decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed.
    Allow,
    /// Allowed; folders only are listed.
    FoldersOnly,
    /// Allowed when the item is a folder.
    IfFolder,
    /// Refused; `NotFound` when the item does not exist.
    DenyUnlessMissing,
    /// Refused.
    Deny,
}

/// What `level` allows for `op` on an item that is `own`.
#[must_use]
pub fn check(level: Level, op: Op, own: Own) -> Verdict {
    let mine = own != Own::No;
    let allow = |yes: bool| if yes { Verdict::Allow } else { Verdict::Deny };
    if level.changes() {
        return Verdict::Allow;
    }
    match op {
        Op::Browse if !level.reads() => Verdict::FoldersOnly,
        Op::Look if !level.reads() && !mine => Verdict::IfFolder,
        Op::Info | Op::Browse | Op::Look => Verdict::Allow,
        Op::ReadLink => allow(level.reads()),
        Op::Read => allow(level.reads() || mine),
        Op::MakeDir | Op::Create => allow(level.adds()),
        Op::Rewrite => allow(level.adds() && own == Own::Writing),
        Op::Remove if level.adds() && !mine => Verdict::DenyUnlessMissing,
        Op::Rename | Op::Remove | Op::SetAttributes => allow(level.adds() && mine),
        Op::Unrestricted => Verdict::Deny,
    }
}

/// Whether an entry of kind `kind` (target `target`) is shown as a folder.
#[must_use]
pub const fn is_folder(kind: u8, target: u8) -> bool {
    kind == entry_kind::DIRECTORY || (kind == entry_kind::SYMLINK && target == entry_kind::DIRECTORY)
}

/// What a finished call makes of the item's ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum After {
    /// It tried to create the item.
    Created,
    /// It wrote the app's item again.
    Rewritten,
    /// It renamed or removed the app's item.
    Gone,
}

/// The item's ownership after a call that ended with `error` (`None`: success); `None`: not the app's.
#[must_use]
pub fn after(before: Own, call: After, error: Option<ErrorName>) -> Own {
    match (call, error) {
        (After::Created | After::Rewritten, None) => Own::Written,
        (After::Created, Some(e)) if made_nothing(e) => Own::No,
        (After::Created, Some(_)) => Own::Writing,
        (After::Gone, None | Some(ErrorName::NotFound)) => Own::No,
        (After::Rewritten | After::Gone, Some(_)) => before,
    }
}

const fn made_nothing(error: ErrorName) -> bool {
    matches!(
        error,
        ErrorName::AlreadyExists
            | ErrorName::PermissionDenied
            | ErrorName::NotFound
            | ErrorName::NotADirectory
            | ErrorName::IsADirectory
            | ErrorName::InvalidName
            | ErrorName::ProtocolError
            | ErrorName::Unsupported
            | ErrorName::ReadOnlyFilesystem
            | ErrorName::AuthFailed
            | ErrorName::ServerIdentityUnknown
            | ErrorName::ServerIdentityChanged
            | ErrorName::SecurityPolicy
            | ErrorName::NetworkUnreachable
            | ErrorName::TooManyConnections
            | ErrorName::RateLimited
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use Op::*;
    use Verdict::{Allow, Deny, DenyUnlessMissing, FoldersOnly, IfFolder};

    #[test]
    fn levels() {
        use Level::{Add, Full, Read, ReadAdd};
        let all = [Full, ReadAdd, Read, Add];
        let words = ["full", "read-add", "read", "add"];
        for (level, word) in all.into_iter().zip(words) {
            assert_eq!(level.as_str(), word);
            assert_eq!(Level::parse(word), Some(level));
        }
        assert_eq!(Level::parse("granted"), None);
        assert_eq!(Level::parse("denied"), None);
        assert_eq!(Level::parse("Full"), None);
        let what = |l: Level| (l.reads(), l.adds(), l.changes());
        assert_eq!(what(Full), (true, true, true));
        assert_eq!(what(ReadAdd), (true, true, false));
        assert_eq!(what(Read), (true, false, false));
        assert_eq!(what(Add), (false, true, false));
        let covered: Vec<(Level, Level)> = all
            .into_iter()
            .flat_map(|a| all.into_iter().map(move |b| (a, b)))
            .filter(|(a, b)| a.covers(*b))
            .collect();
        assert_eq!(
            covered,
            [
                (Full, Full),
                (Full, ReadAdd),
                (Full, Read),
                (Full, Add),
                (ReadAdd, ReadAdd),
                (ReadAdd, Read),
                (ReadAdd, Add),
                (Read, Read),
                (Add, Add)
            ]
        );
    }

    const OPS: [Op; 12] = [
        Info,
        Browse,
        Look,
        ReadLink,
        Read,
        MakeDir,
        Create,
        Rewrite,
        Rename,
        Remove,
        SetAttributes,
        Unrestricted,
    ];

    fn row(level: Level, own: Own) -> Vec<Verdict> {
        OPS.iter().map(|op| check(level, *op, own)).collect()
    }

    #[test]
    fn full_allows_everything() {
        for own in [Own::No, Own::Writing, Own::Written] {
            assert!(row(Level::Full, own).iter().all(|v| *v == Allow));
        }
    }

    #[test]
    fn read_only_reads() {
        let want = [Allow, Allow, Allow, Allow, Allow, Deny, Deny, Deny, Deny, Deny, Deny, Deny];
        for own in [Own::No, Own::Writing, Own::Written] {
            assert_eq!(row(Level::Read, own), want, "{own:?}");
        }
    }

    #[test]
    fn read_and_add() {
        let others =
            [Allow, Allow, Allow, Allow, Allow, Allow, Allow, Deny, Deny, DenyUnlessMissing, Deny, Deny];
        assert_eq!(row(Level::ReadAdd, Own::No), others);
        let writing = [Allow, Allow, Allow, Allow, Allow, Allow, Allow, Allow, Allow, Allow, Allow, Deny];
        assert_eq!(row(Level::ReadAdd, Own::Writing), writing);
        let written = [Allow, Allow, Allow, Allow, Allow, Allow, Allow, Deny, Allow, Allow, Allow, Deny];
        assert_eq!(row(Level::ReadAdd, Own::Written), written);
    }

    #[test]
    fn add_only() {
        let others = [
            Allow,
            FoldersOnly,
            IfFolder,
            Deny,
            Deny,
            Allow,
            Allow,
            Deny,
            Deny,
            DenyUnlessMissing,
            Deny,
            Deny,
        ];
        assert_eq!(row(Level::Add, Own::No), others);
        let writing =
            [Allow, FoldersOnly, Allow, Deny, Allow, Allow, Allow, Allow, Allow, Allow, Allow, Deny];
        assert_eq!(row(Level::Add, Own::Writing), writing);
        let written = [Allow, FoldersOnly, Allow, Deny, Allow, Allow, Allow, Deny, Allow, Allow, Allow, Deny];
        assert_eq!(row(Level::Add, Own::Written), written);
    }

    #[test]
    fn folders() {
        use entry_kind::{DIRECTORY, FILE, SPECIAL, SYMLINK, UNKNOWN};
        assert!(is_folder(DIRECTORY, UNKNOWN));
        assert!(is_folder(SYMLINK, DIRECTORY));
        assert!(!is_folder(SYMLINK, FILE));
        assert!(!is_folder(FILE, DIRECTORY));
        assert!(!is_folder(SPECIAL, DIRECTORY));
        assert!(!is_folder(UNKNOWN, UNKNOWN));
    }

    #[test]
    fn ownership_after_calls() {
        for before in [Own::No, Own::Writing, Own::Written] {
            assert_eq!(after(before, After::Created, None), Own::Written);
            assert_eq!(after(before, After::Rewritten, None), Own::Written);
            assert_eq!(after(before, After::Gone, None), Own::No);
            assert_eq!(after(before, After::Gone, Some(ErrorName::NotFound)), Own::No);
            assert_eq!(after(before, After::Gone, Some(ErrorName::ConnectionLost)), before);
            assert_eq!(after(before, After::Rewritten, Some(ErrorName::Canceled)), before);
        }
        let left_something = [
            ErrorName::Canceled,
            ErrorName::Timeout,
            ErrorName::NoSpace,
            ErrorName::Internal,
            ErrorName::ConnectionLost,
            ErrorName::DirectoryNotEmpty,
            ErrorName::Locked,
        ];
        for e in ErrorName::ALL {
            let want = if left_something.contains(&e) { Own::Writing } else { Own::No };
            assert_eq!(after(Own::No, After::Created, Some(e)), want, "{e}");
        }
    }
}
