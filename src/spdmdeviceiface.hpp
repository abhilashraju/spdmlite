#pragma once
#include "spdm_handshake.hpp"

#include <reactor/sdbus_calls.hpp>
struct SpdmDeviceIface
{
    std::shared_ptr<sdbusplus::asio::connection> conn;
    sdbusplus::asio::object_server dbusServer;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface;
    struct ResponderInfo
    {
        std::string id;
        std::string ep;
        std::string eport;
    };
    ResponderInfo responderInfo;
    SpdmHandler& spdmHandler;
    using AFTERATTESTATION_HANDLER = std::function<void(const std::string&)>;
    AFTERATTESTATION_HANDLER onAttestationStart;
    static constexpr auto busName = "xyz.openbmc_project.spdm";
    static constexpr auto objPath = "/xyz/openbmc_project/spdm/{}";
    static constexpr auto interface = "xyz.openbmc_project.SpdmDevice";
    static constexpr auto signalName = "Attested";
    SpdmDeviceIface(std::shared_ptr<sdbusplus::asio::connection> conn,
                    const ResponderInfo& rInfo, SpdmHandler& handler) :
        conn(conn), dbusServer(conn), responderInfo(rInfo), spdmHandler(handler)
    {
        auto ifacePath = std::format(objPath, responderInfo.id);
        iface = dbusServer.add_interface(ifacePath, interface);
        // test generic properties
        iface->register_method("attest", [this]() { attest(); });

        iface->register_property(
            "Status", false, std::bind_front(&SpdmDeviceIface::setStatus, this),
            std::bind_front(&SpdmDeviceIface::getStatus, this));
        iface->register_property("remote_ip", responderInfo.ep,
                                 sdbusplus::asio::PropertyPermission::readOnly);

        iface->register_property("remote_port", responderInfo.eport,
                                 sdbusplus::asio::PropertyPermission::readOnly);
        iface->register_signal<bool>(signalName); // signal name
        iface->initialize();
        intialiseSpdmHandler();
    }
    void setAttestationStartHandler(AFTERATTESTATION_HANDLER handler)
    {
        onAttestationStart = std::move(handler);
    }
    void attest()
    {
        spdmHandler.setEndPoint(responderInfo.ep, responderInfo.eport);
        spdmHandler.startHandshake();
    }

    bool setStatus(bool newstate, bool& currentstate)
    {
        // if (currentstate == newstate)
        // {
        //     LOG_INFO("Provisioning state is already set to {}", newstate);
        //     return false; // No change needed
        // }
        LOG_INFO("Provisioning state is  set to {}", newstate);
        currentstate = newstate;

        return true; // Return true if successful
    }
    bool getStatus(bool currentstate)
    {
        // This method would get the current provisioning state.
        // Implementation would depend on the specific requirements.
        LOG_INFO("Getting provisioning state: {}", currentstate);
        return currentstate; // Return the current state
    }
    void intialiseSpdmHandler()
    {
        spdmHandler.setSpdmFinishHandler(
            [this](bool status, bool resp) -> net::awaitable<void> {
                LOG_INFO("SPDM Handshake finished with status: {} resp {}",
                         status, resp);
                if (resp)
                {
                    auto [ec] = co_await setProperty(
                        *conn, busName, std::format(objPath, responderInfo.id),
                        interface, "Status", status);
                    if (ec)
                    {
                        LOG_ERROR("Failed to set Status property: {}",
                                  ec.message());

                        co_return;
                    }
                }
                else
                {
                    emitStatus(status);
                }
            });
    }
    void emitStatus(bool status)
    {
        LOG_DEBUG("Emitting spdm status {}", status);
        std::string path = std::format(objPath, responderInfo.id);
        auto msg = conn->new_signal(path.data(), interface, signalName);
        bool value = status;
        msg.append(value);
        msg.signal_send();
    }
};
