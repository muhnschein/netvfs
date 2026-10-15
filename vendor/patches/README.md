# Local patches on vendored libraries

`vendor/build-vendor.sh` applies `vendor/patches/<library>/*.patch` (in name
order) to a copy of the pinned submodule before building, so the submodule
checkout itself stays at the pinned commit (SPEC D-1).

