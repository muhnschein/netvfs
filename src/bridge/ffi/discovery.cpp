// SPDX-License-Identifier: LGPL-2.1-or-later
// Discovery of nearby servers (XD-5), on the Qt thread only (T3). The caller
// decides when it runs and how often it reports (the C++ bridge's
// NearbyService in serverparts.cpp); this part reports every change.
#include "ffi_p.h"

#include "discovery.h"

struct nvb_discovery {
    nvb_discovery_hooks hooks {};
    std::unique_ptr<NetVfs::Discovery> discovery;
    bool running = false;
    bool open = false;               // start() opened a socket
};

namespace NetVfs::Ffi {

namespace {

void report(const nvb_discovery *d)
{
    if (!d->hooks.changed)
        return;
    const QVector<DiscoveredService> services = d->discovery->services();
    HoldArena arena;
    std::vector<nvb_nearby> items(static_cast<size_t>(services.size()));
    for (int i = 0; i < services.size(); ++i) {
        const DiscoveredService &s = services.at(i);
        nvb_nearby &item = items[static_cast<size_t>(i)];
        item.name = arena.bytes(s.instanceName.toUtf8());
        item.provider = arena.bytes(s.provider.toUtf8());
        item.host = arena.bytes(s.host.toUtf8());
        item.port = static_cast<uint16_t>(s.port);
        item.path = arena.bytes(Names::encode(s.path));
    }
    d->hooks.changed(d->hooks.ctx, items.data(), items.size());
}

} // namespace

nvb_discovery *discoveryNew(const nvb_discovery_hooks *hooks) noexcept
{
    return guardedValue<nvb_discovery *>(nullptr, [hooks]() {
        auto d = std::make_unique<nvb_discovery>();
        if (hooks)
            d->hooks = *hooks;
        d->discovery = std::make_unique<Discovery>();
        const nvb_discovery *self = d.get();
        const Discovery *discovery = d->discovery.get();
        // The discovery is the context: no hook call once it is deleted.
        QObject::connect(discovery, &Discovery::found, discovery, [self]() { report(self); });
        QObject::connect(discovery, &Discovery::updated, discovery, [self]() { report(self); });
        QObject::connect(discovery, &Discovery::lost, discovery, [self]() { report(self); });
        return d.release();
    });
}

// Idempotent: Discovery::start()/stop() are reference counted, this holds at
// most one reference.
int32_t discoverySetRunning(nvb_discovery *d, int32_t on) noexcept
{
    return guardedValue<int32_t>(0, [d, on]() {
        if (!d)
            return 0;
        if (on && !d->running) {
            d->running = true;
            d->open = d->discovery->start();
        } else if (!on && d->running) {
            d->running = false;
            d->open = false;
            d->discovery->stop();
        }
        return d->running && d->open ? 1 : 0;
    });
}

void discoveryFree(nvb_discovery *d) noexcept
{
    guardedVoid([d]() {
        std::unique_ptr<nvb_discovery> owned(d);
        if (owned && owned->running)
            owned->discovery->stop();
    });
}

} // namespace NetVfs::Ffi
