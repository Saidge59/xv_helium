VERSION 0.7
ARG --global distro=bookworm
FROM debian:$distro-slim
WORKDIR /hpt

buster-deps:
    RUN echo "deb http://deb.debian.org/debian buster-backports main" | tee -a /etc/apt/sources.list
    RUN apt-get update
    RUN apt-get -y -t buster-backports install --no-install-recommends linux-headers-$(dpkg --print-architecture) dkms

bullseye-deps:
    RUN apt-get update
    RUN apt-get -y install --no-install-recommends linux-headers-$(dpkg --print-architecture) dkms

bookworm-deps:
    RUN apt-get update
    RUN apt-get -y install --no-install-recommends linux-headers-$(dpkg --print-architecture) wget ca-certificates make
    # Use an older version of dkms
    RUN mkdir -p /tmp/dkms
    RUN wget https://github.com/dell/dkms/archive/refs/tags/v2.8.6.tar.gz && tar xf v2.8.6.tar.gz -C /tmp/dkms
    RUN cd /tmp/dkms/dkms-2.8.6 && make install-debian

prep-build:
    FROM +$distro-deps
    RUN apt-get -y install --no-install-recommends build-essential git automake m4 libtool-bin cmake ninja-build meson vim devscripts debhelper sudo
    COPY . .

save-devcontainer:
    FROM +prep-build

    # https://code.visualstudio.com/remote/advancedcontainers/add-nonroot-user
    ARG USERNAME=dev
    ARG USER_UID=1000
    ARG USER_GID=$USER_UID
    RUN groupadd --gid $USER_GID $USERNAME \
        && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
        && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
        && chmod 0440 /etc/sudoers.d/$USERNAME
    USER $USERNAME

    SAVE IMAGE xv_helium_tun:devcontainer

public-headers:
    COPY ./lib/hpt/hpt.h .
    COPY ./lib/hpt/hpt_common.h .
    SAVE ARTIFACT hpt.h $distro/libhpt/hpt.h AS LOCAL artifacts/$distro/libhpt/
    SAVE ARTIFACT hpt_common.h $distro/libhpt/hpt_common.h AS LOCAL artifacts/$distro/libhpt/

build-libhpt:
    FROM +prep-build
    ARG KERNDIR="$(ls -A1 /lib/modules/)"
    ARG ARCH="$(uname -m)"
    ENV DESTDIR=/hpt-build/
    RUN meson setup build -Dkernel_dir=/lib/modules/$KERNDIR
    WORKDIR build
    RUN ninja
    RUN ninja install
    # Save the files we care about
    SAVE ARTIFACT /hpt-build/usr/local/include/hpt.h $distro/libhpt/hpt.h AS LOCAL artifacts/$distro/libhpt/
    SAVE ARTIFACT /hpt-build/usr/local/include/hpt_common.h $distro/libhpt/hpt_common.h AS LOCAL artifacts/$distro/libhpt/
    SAVE ARTIFACT /hpt-build/usr/local/lib/$ARCH-linux-gnu/libhpt.so $distro/libhpt/libhpt.so AS LOCAL artifacts/$distro/libhpt/
    SAVE ARTIFACT /hpt-build/usr/local/lib/$ARCH-linux-gnu/libhpt.a $distro/libhpt/libhpt.a AS LOCAL artifacts/$distro/libhpt/
    SAVE ARTIFACT /hpt-build/lib/modules/* $distro/kernel/ AS LOCAL artifacts/$distro/kernel/

build-packages-libhpt:
    FROM +prep-build
    ARG PACKAGE_VERSION="$(grep PACKAGE_VERSION dkms.conf|cut -f 2 -d=)"
    ENV PACKAGE_VERSION=$PACKAGE_VERSION
    RUN apt-get -y build-dep .
    ARG EARTHLY_TARGET_PROJECT
    RUN dch -Mv $PACKAGE_VERSION "Automated Release from $EARTHLY_TARGET_PROJECT"
    RUN dch -Mr "unstable"
    RUN debuild -us -uc -b
    SAVE ARTIFACT ../*.deb $distro/packages/ AS LOCAL artifacts/$distro/packages/

build-packages-hpt-dkms:
    FROM +prep-build
    ARG PACKAGE_VERSION="$(grep PACKAGE_VERSION dkms.conf|cut -f 2 -d=)"
    ENV PACKAGE_VERSION=$PACKAGE_VERSION
    RUN mkdir -p /usr/src/hpt-$PACKAGE_VERSION/
    RUN cp -a ./* /usr/src/hpt-$PACKAGE_VERSION/
    RUN mkdir -p /etc/dkms/framework.conf.d
    COPY dkms-framework-disable-signing.conf /etc/dkms/framework.conf.d/
    RUN dkms add -m hpt -v $PACKAGE_VERSION
    RUN dkms build -m hpt -v $PACKAGE_VERSION -k $(ls /lib/modules)
    RUN sed -i 's/^Depends:.*/&, meson, ninja-build/' /etc/dkms/template-dkms-mkdeb/debian/control
    RUN dkms mkdeb -m hpt -v $PACKAGE_VERSION
    RUN dkms mkdeb --source-only -m hpt -v $PACKAGE_VERSION
    SAVE ARTIFACT /var/lib/dkms/hpt/${PACKAGE_VERSION}/deb/*.deb $distro/packages/ AS LOCAL artifacts/$distro/packages/

all:
    FROM +prep-build
    BUILD +build-libhpt
    BUILD +build-packages-libhpt
    BUILD +build-packages-hpt-dkms
