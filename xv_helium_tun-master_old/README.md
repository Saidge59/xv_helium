# Helium High-Performance TUN driver

This kernel module is an alternative to the Linux 'tun' driver. This driver memory maps custom ring-buffers into the kernel and userspace at the same time and uses them to pass packets received across instead of syscalls. We have demonstrated significant performance increases with this approach over the standard Linux tun device.

The package also includes a library, libhpt, which simplifies driving of this interface and removes the need to open or ioctl the driver directly. See the helium-server usage for a reference.

# Installation

The CircleCI job will create a Debian package which can be installed directly. The kernel module will be compiled upon install of the .deb.

# Development Install

These steps will install the library and kernel module on your system. This will only work on relatively new Linux kernels (tested on 5.8+).

```$
meson build
cd build
ninja
ninja install
ldconfig
insmod kernel/linux/hpt/hpt.ko
```

## Devcontainer

Using a [devcontainer](https://containers.dev/) allows you to use the
above development flow without installing all the build dependencies
onto your host.

This requires the devcontainer [cli](https://github.com/devcontainers/cli):

```console
$ npm install -g @devcontainers/cli
$ earthly +save-devcontainer
$ devcontainer up --workspace-folder . --remove-existing-container
$ devcontainer exec --workspace-folder . bash
```

At this point you can run the development steps as described above.

# Version bumps

Do not modify/update the Debian `changelog`, this is automated.

An earthly target runs the `dch` command here:
https://github.com/xvpn/xv_helium_tun/blob/996c0fce696243812bf2f566a1dca934946b57cf/Earthfile#L56-L57

Notes in the baseline `changelog` file.
https://github.com/xvpn/xv_helium_tun/blob/master/debian/changelog#L3-L4

## PR's

Each PR will generate it's own changelog update via Circle CI.

## DKMS

If you need to update the DKMS version the following two lines must be updated:
`dkms.conf:PACKAGE_VERSION=X.Y`
`kernel/linux/hpt/hpt_dev.h:#define HPT_VERSION "X.Y"`
