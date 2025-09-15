:tocdepth: 3

base/protocols/rdp/consts.zeek
==============================
.. zeek:namespace:: RDP


:Namespace: RDP

Summary
~~~~~~~
Constants
#########
==================================================================================================== =
:zeek:id:`RDP::builds`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`             
:zeek:id:`RDP::cert_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`         
:zeek:id:`RDP::color_depths`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`       
:zeek:id:`RDP::encryption_levels`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`  
:zeek:id:`RDP::encryption_methods`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
:zeek:id:`RDP::failure_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`      
:zeek:id:`RDP::high_color_depths`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`  
:zeek:id:`RDP::languages`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`          
:zeek:id:`RDP::results`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`            
:zeek:id:`RDP::security_protocols`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
==================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: RDP::builds
   :source-code: base/protocols/rdp/consts.zeek 5 5

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2195] = "RDP 5.0",
            [7601] = "RDP 7.1",
            [6001] = "RDP 6.1",
            [6000] = "RDP 6.0",
            [419] = "RDP 4.0",
            [25282] = "RDP 8.0 (Mac)",
            [3790] = "RDP 5.2",
            [2600] = "RDP 5.1",
            [6002] = "RDP 6.2",
            [2221] = "RDP 5.0",
            [7600] = "RDP 7.0",
            [9600] = "RDP 8.1",
            [25189] = "RDP 8.0 (Mac)",
            [9200] = "RDP 8.0"
         }



.. zeek:id:: RDP::cert_types
   :source-code: base/protocols/rdp/consts.zeek 38 38

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "X.509",
            [1] = "RSA"
         }



.. zeek:id:: RDP::color_depths
   :source-code: base/protocols/rdp/consts.zeek 67 67

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [8] = "32bit",
            [4] = "15bit",
            [2] = "16bit",
            [1] = "24bit"
         }



.. zeek:id:: RDP::encryption_levels
   :source-code: base/protocols/rdp/consts.zeek 51 51

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "None",
            [2] = "Client compatible",
            [4] = "FIPS",
            [1] = "Low",
            [3] = "High"
         }



.. zeek:id:: RDP::encryption_methods
   :source-code: base/protocols/rdp/consts.zeek 43 43

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "None",
            [10] = "FIPS",
            [8] = "56bit",
            [2] = "128bit",
            [1] = "40bit"
         }



.. zeek:id:: RDP::failure_codes
   :source-code: base/protocols/rdp/consts.zeek 29 29

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "SSL_NOT_ALLOWED_BY_SERVER",
            [5] = "HYBRID_REQUIRED_BY_SERVER",
            [3] = "SSL_CERT_NOT_ON_SERVER",
            [6] = "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
            [4] = "INCONSISTENT_FLAGS",
            [1] = "SSL_REQUIRED_BY_SERVER"
         }



.. zeek:id:: RDP::high_color_depths
   :source-code: base/protocols/rdp/consts.zeek 59 59

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [15] = "15bit",
            [16] = "16bit",
            [8] = "8bit",
            [4] = "4bit",
            [24] = "24bit"
         }



.. zeek:id:: RDP::languages
   :source-code: base/protocols/rdp/consts.zeek 84 84

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [1154] = "Occitan",
            [66628] = "Tatar",
            [6153] = "English - Ireland",
            [658432] = "Phags-pa",
            [1080] = "Faroese",
            [67596] = "Belgian (Comma)",
            [11273] = "English - Trinidad",
            [71689] = "Scottish Gaelic",
            [263177] = "English - United States (Dvorak for right hand)",
            [1117184] = "Javanese",
            [1153] = "Maori - New Zealand",
            [1155] = "Corsican",
            [14337] = "Arabic - U.A.E.",
            [1140] = "Guarani - Paraguay",
            [66652] = "Cherokee Nation Phonetic",
            [1033] = "English - United States",
            [1129] = "Ibibio - Nigeria",
            [1053] = "Swedish",
            [12314] = "Serbian (Cyrillic) - Montenegro",
            [1134] = "Luxembourgish",
            [12297] = "English - Zimbabwe",
            [3079] = "German - Austria",
            [2070] = "Portuguese - Portugal",
            [66569] = "English - United States (Dvorak)",
            [5124] = "Chinese - Macao SAR",
            [68608] = "Myanmar",
            [1070] = "Sorbian",
            [1079] = "Georgian",
            [9226] = "Spanish - Colombia",
            [1089] = "Swahili",
            [66650] = "Syriac Phonetic",
            [1105] = "Tibetan - People's Republic of China",
            [17417] = "English - Malaysia",
            [1164] = "Dari",
            [9242] = "Serbian (Latin) - Serbia",
            [1064] = "Tajik",
            [14346] = "Spanish - Uruguay",
            [66604] = "Azerbaijani (Standard)",
            [1109] = "Burmese",
            [1158] = "K'iche",
            [1075] = "Venda",
            [4122] = "Croatian (Bosnia/Herzegovina)",
            [1128] = "Hausa - Nigeria",
            [1137] = "Kanuri - Nigeria",
            [66606] = "Sorbian Extended",
            [986112] = "Old Italic",
            [2141] = "Inuktitut (Latin) - Canada",
            [10249] = "English - Belize",
            [66565] = "Czech (QWERTY)",
            [11265] = "Arabic - Jordan",
            [197634] = "Bulgarian",
            [1081] = "Hindi",
            [1036] = "French - France",
            [1093] = "Bengali (India)",
            [132139] = "Armenian Phonetic",
            [4097] = "Arabic - Libya",
            [1133] = "Bashkir",
            [7227] = "Sami (Southern) - Sweden",
            [1039] = "Icelandic",
            [5146] = "Bosnian (Bosnia/Herzegovina)",
            [1059] = "Belarusian",
            [1088] = "Kyrgyz (Cyrillic)",
            [17418] = "Spanish - El Salvador",
            [22538] = "Spanish - Latin America",
            [6156] = "French - Monaco",
            [66568] = "Uyghur",
            [66641] = "Tibetan (PRC - Standard)",
            [132105] = "English - United States (International)",
            [66562] = "Bulgarian (Latin)",
            [1091] = "Uzbek (Latin)",
            [2128] = "Mongolian (Mongolian)",
            [66590] = "Thai Pattachote",
            [1043] = "Dutch - Netherlands",
            [132098] = "Bulgarian (phonetic layout)",
            [1052] = "Albanian - Albania",
            [1029] = "Czech",
            [2145] = "Nepali - India",
            [6154] = "Spanish - Panama",
            [197662] = "Thai Pattachote (non-ShiftLock)",
            [1115] = "Sinhalese - Sri Lanka",
            [328745] = "Persian (Standard)",
            [132134] = "Latvian (Standard)",
            [1135] = "Greenlandic",
            [9228] = "French - Democratic Rep. of Congo",
            [4155] = "Sami (Lule) - Norway",
            [66619] = "Sami Extended Norway",
            [1090] = "Turkmen",
            [66615] = "Georgian (QWERTY)",
            [199680] = "Tai Le",
            [1152] = "Uighur - China",
            [1065] = "Farsi",
            [10266] = "Serbian (Cyrillic) - Serbia",
            [3098] = "Serbian (Cyrillic)",
            [132151] = "Georgian (Ergonomic)",
            [2144] = "Kashmiri",
            [10241] = "Arabic - Syria",
            [2064] = "Italian - Switzerland",
            [1047] = "Rhaeto-Romanic",
            [1160] = "Wolof",
            [66688] = "Uyghur",
            [3076] = "Chinese - Hong Kong SAR",
            [2067] = "Dutch - Belgium",
            [13313] = "Arabic - Kuwait",
            [132165] = "Bangla (India)",
            [132142] = "Sorbian Standard",
            [2049] = "Arabic - Iraq",
            [132130] = "Ukrainian (Enhanced)",
            [3073] = "Arabic - Egypt",
            [1030] = "Danish",
            [15370] = "Spanish - Paraguay",
            [1131] = "Quecha - Bolivia",
            [1077] = "Zulu",
            [16394] = "Spanish - Bolivia",
            [132135] = "Lithuanian Standard",
            [1026] = "Bulgarian",
            [2055] = "German - Switzerland",
            [1082] = "Maltese",
            [8204] = "French - Reunion",
            [1071] = "FYRO Macedonian",
            [8218] = "Bosnian (Cyrillic) - Bosnia and Herzegovina",
            [12300] = "French - Cote d'Ivoire",
            [461824] = "Lisu (Basic)",
            [13321] = "English - Philippines",
            [1121] = "Nepali",
            [20490] = "Spanish - Puerto Rico",
            [3084] = "French - Canada",
            [69641] = "Canadian Multilingual Standard",
            [2155] = "Quecha - Ecuador",
            [1114] = "Syriac",
            [1066] = "Vietnamese",
            [1092] = "Tatar",
            [5132] = "French - Luxembourg",
            [1132] = "Sepedi",
            [263176] = "Greek (319) Latin",
            [14348] = "French - Morocco",
            [2074] = "Serbian (Latin)",
            [1098] = "Telugu",
            [1156] = "Alsatian",
            [1055] = "Turkish",
            [7178] = "Spanish - Dominican Republic",
            [9275] = "Sami (Inari) - Finland",
            [1083] = "Sami (Lappish)",
            [4106] = "Spanish - Guatemala",
            [3081] = "English - Australia",
            [5129] = "English - New Zealand",
            [1146] = "Mapudungun",
            [1037] = "Hebrew",
            [66598] = "Latvian (Legacy)",
            [1182720] = "Futhark",
            [1159] = "Kinyarwanda",
            [2057] = "English - United Kingdom",
            [2108] = "Irish",
            [1032] = "Greek",
            [1049] = "Russian",
            [2058] = "Spanish - Mexico",
            [132101] = "Czech Programmers",
            [132097] = "Arabic (102) AZERTY",
            [1067] = "Armenian - Armenia",
            [1054] = "Thai",
            [1143] = "Somali",
            [1031] = "German - Germany",
            [4108] = "French - Switzerland",
            [1103] = "Sanskrit",
            [15369] = "English - Hong Kong SAR",
            [133200] = "Mongolian (Mongolian Script - Standard)",
            [66585] = "Russian (Typewriter)",
            [197675] = "Armenian Typewriter",
            [9225] = "English - Caribbean",
            [2151] = "Pular - Senegal",
            [66561] = "Arabic (102)",
            [330752] = "Tifinagh (Basic)",
            [3153] = "Dzongkha",
            [66607] = "Macedonia (FYROM) - Standard",
            [1097] = "Tamil",
            [8201] = "English - Jamaica",
            [15361] = "Arabic - Bahrain",
            [4191] = "Central Atlas Tamazight (Tifinagh) - Morocco",
            [2115] = "Uzbek (Cyrillic)",
            [1062] = "Latvian",
            [4105] = "English - Canada",
            [1120] = "Kashmiri (Arabic)",
            [7169] = "Arabic - Tunisia",
            [2143] = "Tamazight (Latin)",
            [2118] = "Punjabi (Pakistan)",
            [13324] = "French - Mali",
            [66599] = "Lithuanian",
            [3082] = "Spanish - Spain (Modern Sort)",
            [8202] = "Spanish - Venezuela",
            [12289] = "Arabic - Lebanon",
            [7180] = "French - West Indies",
            [66629] = "Bangla (India - Legacy)",
            [67643] = "Finnish with Sami",
            [1142] = "Latin",
            [1074] = "Tswana",
            [1058] = "Ukrainian",
            [5130] = "Spanish - Costa Rica",
            [66603] = "Armenian Western",
            [1141] = "Hawaiian - United States",
            [1042] = "Korean",
            [8193] = "Arabic - Oman",
            [1086] = "Malay - Malaysia",
            [1106] = "Welsh",
            [197641] = "English - United States (Dvorak for left hand)",
            [66643] = "Khmer (NIDA)",
            [1122] = "French - West Indies",
            [1095] = "Gujarati",
            [18442] = "Spanish - Honduras",
            [1099] = "Kannada",
            [1087] = "Kazakh",
            [1094] = "Punjabi",
            [1035] = "Finnish",
            [66581] = "Polish (214)",
            [11274] = "Spanish - Argentina",
            [1069] = "Basque",
            [1111] = "Konkani",
            [1126] = "Edo",
            [3131] = "Sami (Northern) - Finland",
            [10252] = "French - Senegal",
            [1078] = "Afrikaans - South Africa",
            [1068] = "Azeri (Latin)",
            [592896] = "N'ko",
            [1124] = "Filipino",
            [2080] = "Urdu - India",
            [2052] = "Chinese - People's Republic of China",
            [1044] = "Norwegian (Bokmal)",
            [2068] = "Norwegian (Nynorsk)",
            [7177] = "English - South Africa",
            [1051648] = "Sora",
            [1034] = "Spanish - Spain (Traditional Sort)",
            [1028] = "Chinese - Taiwan",
            [66587] = "Slovak (QWERTY)",
            [133179] = "Sami Extended Finland-Sweden",
            [11290] = "Serbian (Latin) - Montenegro",
            [1084] = "Scottish Gaelic",
            [13322] = "Spanish - Chile",
            [132126] = "Thai Kedmanee (non-ShiftLock)",
            [6170] = "Serbian (Latin) - Bosnia and Herzegovina",
            [66584] = "Romanian (Standard)",
            [1051] = "Slovak",
            [66618] = "Maltese 48-key",
            [1096] = "Oriya",
            [2110] = "Malay - Brunei Darussalam",
            [31748] = "Chinese - Traditional",
            [328712] = "Greek Latin",
            [1116] = "Cherokee - United States",
            [396288] = "Tifinagh (Full)",
            [66567] = "German (IBM)",
            [58380] = "French - North Africa",
            [1038] = "Hungarian",
            [1061] = "Estonian",
            [16385] = "Arabic - Qatar",
            [527360] = "Lisu (Standard)",
            [1112] = "Manipuri",
            [789504] = "Gothic",
            [2060] = "French - Belgium",
            [16393] = "English - India",
            [132120] = "Romanian (Programmers)",
            [1025] = "Arabic - Saudi Arabia",
            [1119] = "Tamazight (Arabic)",
            [1104] = "Mongolian (Cyrillic)",
            [2129] = "Tibetan - Bhutan",
            [15372] = "French - Haiti",
            [1073] = "Tsonga",
            [66617] = "Hindi Traditional",
            [6203] = "Sami (Southern) - Norway",
            [19466] = "Spanish - Nicaragua",
            [5179] = "Sami (Lule) - Sweden",
            [6145] = "Arabic - Morocco",
            [1117] = "Inuktitut",
            [1138] = "Oromo",
            [197687] = "Georgian Ministry of Education and Science Schools",
            [263170] = "Bulgarian (phonetic traditional)",
            [920576] = "Osmanya",
            [10250] = "Spanish - Peru",
            [1041] = "Japanese",
            [4100] = "Chinese - Singapore",
            [21514] = "Spanish - United States",
            [1056] = "Urdu",
            [2121] = "Tamil - Sri Lanka",
            [1100] = "Malayalam",
            [1102] = "Marathi",
            [1125] = "Divehi",
            [1101] = "Assamese",
            [132121] = "Russian - Mnemonic",
            [2137] = "Sindhi - Pakistan",
            [2072] = "Romanian - Moldava",
            [2092] = "Azeri (Cyrillic)",
            [1130] = "Yoruba",
            [1127] = "Fulfulde - Nigeria",
            [1148] = "Mohawk",
            [66576] = "Italian (142)",
            [1139] = "Tigrigna - Ethiopia",
            [1048] = "Romanian",
            [12298] = "Spanish - Ecuador",
            [66570] = "Spanish Variation",
            [1110] = "Galician",
            [5121] = "Arabic - Algeria",
            [18441] = "English - Singapore",
            [2077] = "Swedish - Finland",
            [1076] = "Xhosa",
            [66582] = "Portuguese (Brazilian ABNT2)",
            [1108] = "Lao",
            [2073] = "Russian - Moldava",
            [263223] = "Georgian (Old Alphabets)",
            [1136] = "Igbo - Nigeria",
            [197640] = "Greek (220) Latin",
            [1150] = "Breton",
            [1113] = "Sindhi - India",
            [1050] = "Croatian",
            [1157] = "Yakut",
            [4103] = "German - Luxembourg",
            [394248] = "Greek Polytonic",
            [132104] = "Greek (319)",
            [1123] = "Pashto",
            [66651] = "Sinhala - wij 9",
            [8251] = "Sami (Skolt) - Finland",
            [1057] = "Indonesian",
            [2163] = "Tigrigna - Eritrea",
            [11276] = "French - Cameroon",
            [9217] = "Arabic - Yemen",
            [1107] = "Khmer",
            [2117] = "Bengali (Bangladesh)",
            [1063] = "Lithuanian",
            [1085] = "Yiddish",
            [14345] = "English - Indonesia",
            [855040] = "Ol Chiki",
            [1279] = "HID (Human Interface Device)",
            [1072] = "Sutu",
            [2107] = "Sami (Northern) - Sweden",
            [3179] = "Quecha - Peru\x09CB",
            [1145] = "Papiamentu",
            [5127] = "German - Liechtenstein",
            [66574] = "Hungarian 101-key",
            [1144] = "Yi",
            [66653] = "Inuktitut - Naqittaut",
            [1027] = "Catalan",
            [1060] = "Slovenian",
            [1046] = "Portuguese - Brazil",
            [1118] = "Amharic - Ethiopia",
            [723968] = "Buginese",
            [1040] = "Italian - Italy",
            [66661] = "Divehi Typewriter",
            [134144] = "New Tai Lue",
            [66591] = "Turkish F",
            [1045] = "Polish"
         }



.. zeek:id:: RDP::results
   :source-code: base/protocols/rdp/consts.zeek 74 74

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "Success",
            [2] = "Resources not available",
            [4] = "Locked conference",
            [1] = "User rejected",
            [3] = "Rejected for symmetry breaking"
         }



.. zeek:id:: RDP::security_protocols
   :source-code: base/protocols/rdp/consts.zeek 22 22

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "RDP",
            [8] = "HYBRID_EX",
            [2] = "HYBRID",
            [1] = "SSL"
         }




