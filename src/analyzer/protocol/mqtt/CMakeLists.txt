
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek MQTT)
zeek_plugin_cc(MQTT.cc Plugin.cc)
zeek_plugin_bif(types.bif events.bif)
zeek_plugin_pac(mqtt.pac
                mqtt-protocol.pac
                commands/connect.pac
                commands/connack.pac
                commands/publish.pac
                commands/puback.pac
                commands/pubrec.pac
                commands/pubrel.pac
                commands/pubcomp.pac
                commands/subscribe.pac
                commands/suback.pac
                commands/unsuback.pac
                commands/unsubscribe.pac
                commands/disconnect.pac
                commands/pingreq.pac
                commands/pingresp.pac
                )
zeek_plugin_end()
