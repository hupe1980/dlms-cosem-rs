//! The interface class registry.
//!
//! One declarative table. Adding a class means adding an entry here and nothing else:
//! the descriptor, the lookup, the type and the translator's labels all come from it.
//!
//! Classes are tabulated at two depths. The ones in general use carry their full
//! attribute and method lists; the rest carry a name and version so that a translator
//! can still label an object and a generic server can still host it, which is more than
//! refusing to decode it would give anyone.

use super::class::{
    AttrType::{
        Any, Array, BitString, Boolean, DateTime, DoubleLongUnsigned, Enum, Integer, Long, LongUnsigned,
        ObisCode, OctetString, ScalerUnit, Structure, Unsigned,
    },
    AttributeInfo, ClassDescriptor,
    DefaultAccess::{Read, ReadWrite, Write},
    MethodInfo,
};

macro_rules! interface_classes {
    ($(
        $(#[$meta:meta])*
        $type_name:ident = $id:literal v $ver:literal, $name:literal {
            $( $ai:literal $aname:literal : $aty:ident $acc:ident; )*
            $( fn $mi:literal $mname:literal; )*
        }
    )*) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
            pub struct $type_name;

            impl super::class::InterfaceClass for $type_name {
                const CLASS_ID: u16 = $id;
                const VERSION: u8 = $ver;
                const NAME: &'static str = $name;

                fn descriptor() -> &'static ClassDescriptor {
                    &ClassDescriptor {
                        class_id: $id,
                        version: $ver,
                        name: $name,
                        attributes: &[
                            $(AttributeInfo { index: $ai, name: $aname, ty: $aty, access: $acc },)*
                        ],
                        methods: &[
                            $(MethodInfo { index: $mi, name: $mname },)*
                        ],
                    }
                }
            }
        )*

        /// Every class with a full attribute table.
        pub static DETAILED: &[ClassDescriptor] = &[
            $(ClassDescriptor {
                class_id: $id,
                version: $ver,
                name: $name,
                attributes: &[
                    $(AttributeInfo { index: $ai, name: $aname, ty: $aty, access: $acc },)*
                ],
                methods: &[
                    $(MethodInfo { index: $mi, name: $mname },)*
                ],
            },)*
        ];
    };
}

macro_rules! class_names {
    ($( $id:literal v $ver:literal $name:literal; )*) => {
        /// Classes whose name and version are tabulated but whose attributes are not.
        pub static NAMED: &[ClassDescriptor] = &[
            $(ClassDescriptor { class_id: $id, version: $ver, name: $name, attributes: &[], methods: &[] },)*
        ];
    };
}

interface_classes! {
    /// A value with no semantics of its own beyond its logical name.
    Data = 1 v 0, "Data" {
        1 "logical_name": ObisCode Read;
        2 "value": Any ReadWrite;
    }

    /// A measured value with a scaler, a unit and a status.
    Register = 3 v 0, "Register" {
        1 "logical_name": ObisCode Read;
        2 "value": Any ReadWrite;
        3 "scaler_unit": ScalerUnit Read;
        fn 1 "reset";
    }

    /// A register that also captures the time and status of its value.
    ExtendedRegister = 4 v 0, "Extended register" {
        1 "logical_name": ObisCode Read;
        2 "value": Any ReadWrite;
        3 "scaler_unit": ScalerUnit Read;
        4 "status": Any Read;
        5 "capture_time": DateTime Read;
        fn 1 "reset";
    }

    /// A register holding a demand value computed over a period.
    DemandRegister = 5 v 0, "Demand register" {
        1 "logical_name": ObisCode Read;
        2 "current_average_value": Any Read;
        3 "last_average_value": Any Read;
        4 "scaler_unit": ScalerUnit Read;
        5 "status": Any Read;
        6 "capture_time": DateTime Read;
        7 "start_time_current": DateTime Read;
        8 "period": DoubleLongUnsigned ReadWrite;
        9 "number_of_periods": LongUnsigned ReadWrite;
        fn 1 "reset";
        fn 2 "next_period";
    }

    /// Switches a set of registers between tariff rates.
    RegisterActivation = 6 v 0, "Register activation" {
        1 "logical_name": ObisCode Read;
        2 "register_assignment": Array ReadWrite;
        3 "mask_list": Array ReadWrite;
        4 "active_mask": OctetString Read;
        fn 1 "add_register";
        fn 2 "add_mask";
        fn 3 "delete_mask";
    }

    /// A buffer of captured rows: the load profile, the event log, the billing profile.
    ProfileGeneric = 7 v 1, "Profile generic" {
        1 "logical_name": ObisCode Read;
        2 "buffer": Array ReadWrite;
        3 "capture_objects": Array ReadWrite;
        4 "capture_period": DoubleLongUnsigned ReadWrite;
        5 "sort_method": Enum ReadWrite;
        6 "sort_object": Structure ReadWrite;
        7 "entries_in_use": DoubleLongUnsigned Read;
        8 "profile_entries": DoubleLongUnsigned ReadWrite;
        fn 1 "reset";
        fn 2 "capture";
    }

    /// The meter's clock, its time zone and its daylight-saving rules.
    Clock = 8 v 0, "Clock" {
        1 "logical_name": ObisCode Read;
        2 "time": DateTime ReadWrite;
        3 "time_zone": Long ReadWrite;
        4 "status": Unsigned Read;
        5 "daylight_savings_begin": DateTime ReadWrite;
        6 "daylight_savings_end": DateTime ReadWrite;
        7 "daylight_savings_deviation": Integer ReadWrite;
        8 "daylight_savings_enabled": Boolean ReadWrite;
        9 "clock_base": Enum ReadWrite;
        fn 1 "adjust_to_quarter";
        fn 2 "adjust_to_measuring_period";
        fn 3 "adjust_to_minute";
        fn 4 "adjust_to_preset_time";
        fn 5 "preset_adjusting_time";
        fn 6 "shift_time";
    }

    /// Named sequences of actions other objects can trigger.
    ScriptTable = 9 v 0, "Script table" {
        1 "logical_name": ObisCode Read;
        2 "scripts": Array ReadWrite;
        fn 1 "execute";
    }

    /// Times at which scripts run.
    Schedule = 10 v 0, "Schedule" {
        1 "logical_name": ObisCode Read;
        2 "entries": Array ReadWrite;
        fn 1 "enable_disable";
        fn 2 "insert";
        fn 3 "delete";
    }

    /// Dates on which a different day profile applies.
    SpecialDaysTable = 11 v 0, "Special days table" {
        1 "logical_name": ObisCode Read;
        2 "entries": Array ReadWrite;
        fn 1 "insert";
        fn 2 "delete";
    }

    /// The objects and access rights of an association, addressed by logical name.
    AssociationLn = 15 v 3, "Association LN" {
        1 "logical_name": ObisCode Read;
        2 "object_list": Array Read;
        3 "associated_partners_id": Structure Read;
        4 "application_context_name": OctetString Read;
        5 "xdlms_context_info": Structure Read;
        6 "authentication_mechanism_name": OctetString Read;
        7 "secret": OctetString Write;
        8 "association_status": Enum Read;
        9 "security_setup_reference": ObisCode Read;
        10 "user_list": Array ReadWrite;
        11 "current_user": Structure Read;
        fn 1 "reply_to_hls_authentication";
        fn 2 "change_hls_secret";
        fn 3 "add_object";
        fn 4 "remove_object";
        fn 5 "add_user";
        fn 6 "remove_user";
    }

    /// Which logical device answers on which service access point.
    SapAssignment = 17 v 0, "SAP assignment" {
        1 "logical_name": ObisCode Read;
        2 "sap_assignment_list": Array Read;
        fn 1 "connect_logical_device";
    }

    /// Firmware update: transfer an image in blocks, verify it, then activate it.
    ImageTransfer = 18 v 0, "Image transfer" {
        1 "logical_name": ObisCode Read;
        2 "image_block_size": DoubleLongUnsigned Read;
        3 "image_transferred_blocks_status": BitString Read;
        4 "image_first_not_transferred_block_number": DoubleLongUnsigned Read;
        5 "image_transfer_enabled": Boolean ReadWrite;
        6 "image_transfer_status": Enum Read;
        7 "image_to_activate_info": Array Read;
        fn 1 "image_transfer_initiate";
        fn 2 "image_block_transfer";
        fn 3 "image_verify";
        fn 4 "image_activate";
    }

    /// The tariff calendar: seasons, weeks and day profiles.
    ActivityCalendar = 20 v 0, "Activity calendar" {
        1 "logical_name": ObisCode Read;
        2 "calendar_name_active": OctetString Read;
        3 "season_profile_active": Array Read;
        4 "week_profile_table_active": Array Read;
        5 "day_profile_table_active": Array Read;
        6 "calendar_name_passive": OctetString ReadWrite;
        7 "season_profile_passive": Array ReadWrite;
        8 "week_profile_table_passive": Array ReadWrite;
        9 "day_profile_table_passive": Array ReadWrite;
        10 "activate_passive_calendar_time": DateTime ReadWrite;
        fn 1 "activate_passive_calendar";
    }

    /// Watches a value and runs a script when it crosses a threshold.
    RegisterMonitor = 21 v 0, "Register monitor" {
        1 "logical_name": ObisCode Read;
        2 "thresholds": Array ReadWrite;
        3 "monitored_value": Structure ReadWrite;
        4 "actions": Array ReadWrite;
    }

    /// Runs one script at one time.
    SingleActionSchedule = 22 v 0, "Single action schedule" {
        1 "logical_name": ObisCode Read;
        2 "executed_script": Structure ReadWrite;
        3 "type": Enum ReadWrite;
        4 "execution_time": Array ReadWrite;
    }

    /// The HDLC link's addresses and timeouts.
    IecHdlcSetup = 23 v 1, "IEC HDLC setup" {
        1 "logical_name": ObisCode Read;
        2 "comm_speed": Enum ReadWrite;
        3 "window_size_transmit": Unsigned ReadWrite;
        4 "window_size_receive": Unsigned ReadWrite;
        5 "max_info_field_length_transmit": LongUnsigned ReadWrite;
        6 "max_info_field_length_receive": LongUnsigned ReadWrite;
        7 "inter_octet_time_out": LongUnsigned ReadWrite;
        8 "inactivity_time_out": LongUnsigned ReadWrite;
        9 "device_address": LongUnsigned Read;
    }

    /// Where a value is captured to, and how a display is composed.
    CompactData = 62 v 1, "Compact data" {
        1 "logical_name": ObisCode Read;
        2 "buffer": OctetString Read;
        3 "capture_objects": Array ReadWrite;
        4 "template_id": Unsigned ReadWrite;
        5 "template_description": OctetString Read;
        6 "capture_method": Enum ReadWrite;
        fn 1 "reset";
        fn 2 "capture";
    }

    /// Keys, certificates and the security policy of an association.
    SecuritySetup = 64 v 1, "Security setup" {
        1 "logical_name": ObisCode Read;
        2 "security_policy": Unsigned Read;
        3 "security_suite": Enum Read;
        4 "client_system_title": OctetString Read;
        5 "server_system_title": OctetString Read;
        6 "certificates": Array Read;
        fn 1 "security_activate";
        fn 2 "key_transfer";
        fn 3 "key_agreement";
        fn 4 "generate_key_pair";
        fn 5 "generate_certificate_request";
        fn 6 "import_certificate";
        fn 7 "export_certificate";
        fn 8 "remove_certificate";
    }

    /// The breaker: connect, disconnect, and the rules for each.
    DisconnectControl = 70 v 2, "Disconnect control" {
        1 "logical_name": ObisCode Read;
        2 "output_state": Boolean Read;
        3 "control_state": Enum Read;
        4 "control_mode": Enum ReadWrite;
        fn 1 "remote_disconnect";
        fn 2 "remote_reconnect";
    }

    /// Limits a monitored value, disconnecting or running a script when it is exceeded.
    Limiter = 71 v 0, "Limiter" {
        1 "logical_name": ObisCode Read;
        2 "monitored_value": Structure Read;
        3 "threshold_active": Any Read;
        4 "threshold_normal": Any ReadWrite;
        5 "threshold_emergency": Any ReadWrite;
        6 "min_over_threshold_duration": DoubleLongUnsigned ReadWrite;
        7 "min_under_threshold_duration": DoubleLongUnsigned ReadWrite;
        8 "emergency_profile": Structure ReadWrite;
        9 "emergency_profile_group_id_list": Array ReadWrite;
        10 "emergency_profile_active": Boolean Read;
        11 "actions": Structure ReadWrite;
    }

    /// Where and when the meter pushes data on its own initiative.
    PushSetup = 40 v 3, "Push setup" {
        1 "logical_name": ObisCode Read;
        2 "push_object_list": Array ReadWrite;
        3 "send_destination_and_method": Structure ReadWrite;
        4 "communication_window": Array ReadWrite;
        5 "randomisation_start_interval": LongUnsigned ReadWrite;
        6 "number_of_retries": Unsigned ReadWrite;
        7 "repetition_delay": LongUnsigned ReadWrite;
        8 "port_reference": ObisCode Read;
        9 "push_client_sap": Integer ReadWrite;
        10 "push_protection_parameters": Array ReadWrite;
        11 "push_operation_method": Enum ReadWrite;
        12 "confirmation_parameters": Structure ReadWrite;
        13 "last_confirmation_date_time": DateTime Read;
        fn 1 "push";
        fn 2 "reset";
    }

    /// The TCP or UDP endpoint the wrapper runs over.
    TcpUdpSetup = 41 v 0, "TCP-UDP setup" {
        1 "logical_name": ObisCode Read;
        2 "tcp_udp_port": LongUnsigned ReadWrite;
        3 "ip_reference": ObisCode ReadWrite;
        4 "mss": LongUnsigned ReadWrite;
        5 "nb_of_sim_conn": Unsigned ReadWrite;
        6 "inactivity_time_out": LongUnsigned ReadWrite;
    }

    /// Cryptographic protection of a value independent of the association.
    DataProtection = 30 v 0, "Data protection" {
        1 "logical_name": ObisCode Read;
        2 "protection_buffer": Array Read;
        3 "protection_object_list": Array ReadWrite;
        fn 1 "get_protected_attributes";
        fn 2 "set_protected_attributes";
        fn 3 "invoke_protected_method";
    }

    /// A device's attestation token and qualification declaration.
    Attestation = 170 v 0, "Attestation" {
        1 "logical_name": ObisCode Read;
        2 "attestation_token": OctetString Read;
        3 "qualification_declaration": OctetString Read;
        fn 1 "generate_attestation_token";
    }
}

class_names! {
    12 v 4 "Association SN";
    19 v 1 "IEC local port setup";
    24 v 1 "IEC twisted pair (1) setup";
    25 v 0 "M-Bus slave port setup";
    26 v 0 "Utility tables";
    27 v 1 "Modem configuration";
    28 v 2 "Auto answer";
    29 v 2 "Auto connect";
    42 v 0 "IPv4 setup";
    43 v 0 "MAC address setup";
    44 v 0 "PPP setup";
    45 v 0 "GPRS modem setup";
    46 v 0 "SMTP setup";
    47 v 2 "GSM diagnostic";
    48 v 0 "IPv6 setup";
    50 v 1 "S-FSK Phy&MAC setup";
    51 v 0 "S-FSK Active initiator";
    52 v 0 "S-FSK MAC synchronization timeouts";
    53 v 0 "S-FSK MAC counters";
    55 v 1 "IEC 61334-4-32 LLC setup";
    56 v 0 "S-FSK Reporting system list";
    57 v 0 "ISO/IEC 8802-2 LLC Type 1 setup";
    58 v 0 "ISO/IEC 8802-2 LLC Type 2 setup";
    59 v 0 "ISO/IEC 8802-2 LLC Type 3 setup";
    61 v 0 "Register table";
    63 v 0 "Status mapping";
    65 v 1 "Parameter monitor";
    66 v 0 "Measurement data monitoring";
    67 v 0 "Sensor manager";
    68 v 0 "Arbitrator";
    72 v 2 "M-Bus client";
    73 v 1 "Wireless Mode Q channel";
    74 v 0 "M-Bus master port setup";
    76 v 0 "DLMS server M-Bus port setup";
    77 v 0 "M-Bus diagnostic";
    80 v 0 "61334-4-32 LLC SSCS setup";
    81 v 0 "PRIME NB OFDM PLC Physical layer counters";
    82 v 0 "PRIME NB OFDM PLC MAC setup";
    83 v 0 "PRIME NB OFDM PLC MAC functional parameters";
    84 v 0 "PRIME NB OFDM PLC MAC counters";
    85 v 0 "PRIME NB OFDM PLC MAC network administration data";
    86 v 0 "PRIME NB OFDM PLC Application identification";
    90 v 1 "G3-PLC MAC layer counters";
    91 v 4 "G3-PLC MAC setup";
    92 v 4 "G3-PLC 6LoWPAN adaptation layer setup";
    95 v 0 "Wi-SUN setup";
    96 v 0 "Wi-SUN diagnostic";
    97 v 0 "RPL diagnostic";
    98 v 0 "MPL diagnostic";
    100 v 0 "NTP setup";
    101 v 0 "ZigBee SAS startup";
    102 v 0 "ZigBee SAS join";
    103 v 0 "ZigBee SAS APS fragmentation";
    104 v 0 "ZigBee network control";
    105 v 0 "ZigBee tunnel setup";
    111 v 0 "Account";
    112 v 0 "Credit";
    113 v 0 "Charge";
    115 v 0 "Token gateway";
    116 v 0 "IEC 62055-41 attributes";
    122 v 0 "Function control";
    123 v 0 "Array manager";
    124 v 0 "Communication port protection";
    130 v 0 "ISO/IEC 14908 identification";
    131 v 0 "ISO/IEC 14908 protocol setup";
    132 v 0 "ISO/IEC 14908 protocol status";
    133 v 0 "ISO/IEC 14908 diagnostic";
    140 v 0 "HS-PLC ISO/IEC 12139-1 MAC setup";
    141 v 0 "HS-PLC ISO/IEC 12139-1 CPAS setup";
    142 v 0 "HS-PLC ISO/IEC 12139-1 IP SSAS setup";
    143 v 0 "HS-PLC ISO/IEC 12139-1 HDLC SSAS setup";
    151 v 1 "LTE monitoring";
    152 v 0 "CoAP setup";
    153 v 0 "CoAP diagnostic";
    160 v 0 "G3-PLC Hybrid RF MAC layer counters";
    161 v 1 "G3-PLC Hybrid RF MAC setup";
    162 v 1 "G3-PLC Hybrid 6LoWPAN adaptation layer setup";
}
