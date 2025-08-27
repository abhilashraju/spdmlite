SUMMARY = "Spdmlite service"
DESCRIPTION = "Spdmlite service"
HOMEPAGE = "https://github.com/abhilashraju/spdmlite service"

LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=cca3a276950ee5cf565f9a7fc281c482"
DEPENDS = " \
    boost \
    gtest \
    nlohmann-json \
    openssl \
    systemd \
    libarchive \
    sdeventplus \
    coroserver \
    sdbusplus \
"

SRC_URI = "git://github.com/abhilashraju/spdmlite.git;branch=main;protocol=https"
SRCREV = "${AUTOREV}"

S = "${WORKDIR}/git"

inherit systemd
inherit pkgconfig meson

EXTRA_OEMESON = " \
    --buildtype=minsize \
"

# Specify the source directory
S = "${WORKDIR}/git"

# Specify the installation directory
bindir = "/usr/bin"
systemd_system_unitdir = "/etc/systemd/system"
etc_dbus_conf = "/etc/dbus-1/system.d"
#do_install() {
#     install -d ${D}${bindir}
#     install -m 0755 ${B}/provisioningd ${D}${bindir}/spdmlite
#     install -d ${D}${systemd_system_unitdir}
#     install -d ${D}${etc_dbus_conf}
#     
#     
#     install -m 0644 ${S}/service/xyz.openbmc_project.spdmlite.service ${D}${systemd_system_unitdir}/
#     install -m 0644 ${S}/service/xyz.openbmc_project.spdmlite.conf ${D}${etc_dbus_conf}/
#}

FILES:${PN} += "/usr/bin/spdmlite"
FILES:${PN} += "/etc/systemd/system/xyz.openbmc_project.spdmlite.service"
FILES:${PN} += "/etc/dbus-1/system.d/xyz.openbmc_project.spdmlite.conf"
FILES:${PN} += "/var/spdm/spdm.conf"
FILES:${PN} += "/etc/ssl/certs/https/server_cert.pem"
FILES:${PN} += "/etc/ssl/private/server_key.pem"
FILES:${PN} += "/etc/ssl/certs/https/client_cert.pem"
FILES:${PN} += "/etc/ssl/private/client_key.pem"
FILES:${PN} += "/etc/ssl/private/server_key.pem"
FILES:${PN} += "/etc/ssl/certs/https/server_cert.pem"

