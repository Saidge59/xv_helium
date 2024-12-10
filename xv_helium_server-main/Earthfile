VERSION 0.7
ARG --global distro=bookworm
FROM debian:$distro-slim
WORKDIR /helium-server/

setup-build-env:
    RUN apt-get -y update
    RUN apt-get -y install --no-install-recommends build-essential vim git devscripts debhelper sudo libsqlite3-dev rubygems wget automake cmake libreadline-dev libtool liblua5.3-dev lua5.3 libssl-dev bash
    RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
    RUN echo "deb http://apt.llvm.org/$distro/ llvm-toolchain-$distro-17 main" | sudo tee -a /etc/apt/sources.list.d/clang.list
    RUN echo "deb-src http://apt.llvm.org/$distro/ llvm-toolchain-$distro-17 main" | sudo tee -a /etc/apt/sources.list.d/clang.list
    RUN sudo apt-get update
    RUN sudo apt-get install --no-install-recommends -y llvm-17 clang-17 clang-format-17 libclang-rt-17-dev
    RUN sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100
    RUN sudo gem install ceedling --no-user-install
    ENV CC=clang
    ENV CCLD=clang

deps-build-debs:
    FROM +setup-build-env

    # Pull and build internal deb packages
    COPY (github.com/xvpn/xv_luarocks+build-deb/$distro/packages/*.deb --distro=$distro) ./deb/
    COPY (github.com/xvpn/xv_helium_tun:v1.7+build-packages-libhpt/$distro/packages/*.deb --distro=$distro) ./deb/
    COPY (github.com/xvpn/xv_libballoon:v1.24.0+build-xenon-deb/*.deb --distro=$distro) ./deb/
    SAVE ARTIFACT deb/*.deb AS LOCAL artifacts/

deps:
    FROM +deps-build-debs

    # Install build time dependencies
    COPY --dir ./debian ./debian
    RUN apt-get --reinstall --allow-downgrades --allow-change-held-packages -yy install ./deb/*.deb

    # Strip restrictive dependency pinning before installing the development dependencies
    RUN sed -i '/libxenon/c\ libxenon,' debian/control
    RUN sed -i '/luarocks/c\ luarocks,' debian/control

    # Install the build dependencies of helium-server (defined in debian/control)
    RUN apt-get -y build-dep --no-install-recommends .

    # Install lua dependencies which are required by tests
    RUN sudo luarocks install lsqlite3
    RUN sudo luarocks install lua-crypt
    RUN sudo luarocks install setuid
    RUN sudo luarocks install inspect
    RUN sudo luarocks install busted

clobber:
    FROM +deps
    RUN /usr/local/bin/ceedling clobber

build-dep-copy:
    FROM +deps
    # Copy the ceedling project file and patches only, so that Earthly only rebuild dependencies when the project.yml changes
    COPY --dir --keep-ts project.yml patches ./
    COPY --dir ./scripts ./scripts
    COPY --dir ./.git ./.git
    # Creating skeleton folders to make 'ceedling dependencies:fetch' happy
    RUN mkdir -p src include test/support \
        third_party/argparse \
        third_party/lightway_core \
        third_party/jemalloc \
        third_party/libuv \
        third_party/msgpack \
        third_party/zlog \
        third_party/statsd

build-deps:
    FROM +build-dep-copy
    # Build all 3rdparty dependencies
    RUN /usr/local/bin/ceedling verbosity[4] dependencies:fetch
    RUN /usr/local/bin/ceedling verbosity[4] dependencies:make

build-copy:
    FROM +build-deps
    # Copy in the source and include files
    COPY --dir --keep-ts src include ./

build:
    FROM +build-copy
    # Generate the release
    RUN /usr/local/bin/ceedling verbosity[4] release
    # Store the artifacts
    SAVE ARTIFACT build/release/helium-server.out AS LOCAL build/release/helium-server

test-copy:
    FROM +build-copy
    # Copy in the files required by tests
    COPY --dir test lua ./

test-deps:
    FROM +test-copy
    # Build lua-jwt
    RUN cd lua/lua-jwt; sudo luarocks build

test-c:
    ARG test_cases=all
    FROM +test-deps
    # Run the tests
    RUN --no-cache ./scripts/run-tests $test_cases
    # Parse ceedling test results
    RUN --no-cache ./scripts/parse-test-results build/test/test-results.out
    RUN --no-cache mv report.xml build/test/
    SAVE ARTIFACT build/test AS LOCAL build/

test-lua:
    FROM +test-deps
    RUN --no-cache cd lua/lua-jwt; busted
    RUN --no-cache cd lua; busted

test:
    BUILD +test-c
    BUILD +test-lua

# Build the helium-server debian package
build-helium-server:
    FROM +build
    COPY --dir debian ./
    COPY --dir lua ./
    COPY helium.tmpfiles.conf ./
    RUN debuild -eCC -eCCLD -us -uc -b
    SAVE ARTIFACT ../*.deb / AS LOCAL artifacts/

save-devcontainer:
    FROM +test-deps

    # https://code.visualstudio.com/remote/advancedcontainers/add-nonroot-user
    ARG USERNAME=dev
    ARG USER_UID=1000
    ARG USER_GID=$USER_UID
    RUN groupadd --gid $USER_GID $USERNAME \
        && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
        && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
        && chmod 0440 /etc/sudoers.d/$USERNAME
    USER $USERNAME

    SAVE IMAGE xv_helium_server:devcontainer
