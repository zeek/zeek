:tocdepth: 3

base/protocols/rdp/consts.bro
=============================
.. bro:namespace:: RDP


:Namespace: RDP

Summary
~~~~~~~
Constants
#########
====================================================================================================================== =
:bro:id:`RDP::builds`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`             
:bro:id:`RDP::cert_types`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`         
:bro:id:`RDP::color_depths`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`       
:bro:id:`RDP::encryption_levels`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`  
:bro:id:`RDP::encryption_methods`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` 
:bro:id:`RDP::failure_codes`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`      
:bro:id:`RDP::high_color_depths`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`  
:bro:id:`RDP::languages`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`          
:bro:id:`RDP::results`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`            
:bro:id:`RDP::security_protocols`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` 
====================================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: RDP::builds

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [6000] = "RDP 6.0",
         [6001] = "RDP 6.1",
         [7600] = "RDP 7.0",
         [6002] = "RDP 6.2",
         [25189] = "RDP 8.0 (Mac)",
         [7601] = "RDP 7.1",
         [9600] = "RDP 8.1",
         [25282] = "RDP 8.0 (Mac)",
         [2195] = "RDP 5.0",
         [3790] = "RDP 5.2",
         [419] = "RDP 4.0",
         [2221] = "RDP 5.0",
         [2600] = "RDP 5.1",
         [9200] = "RDP 8.0"
      }


.. bro:id:: RDP::cert_types

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "X.509",
         [1] = "RSA"
      }


.. bro:id:: RDP::color_depths

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "16bit",
         [4] = "15bit",
         [1] = "24bit",
         [8] = "32bit"
      }


.. bro:id:: RDP::encryption_levels

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "Client compatible",
         [4] = "FIPS",
         [1] = "Low",
         [0] = "None",
         [3] = "High"
      }


.. bro:id:: RDP::encryption_methods

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "128bit",
         [1] = "40bit",
         [8] = "56bit",
         [10] = "FIPS",
         [0] = "None"
      }


.. bro:id:: RDP::failure_codes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "SSL_NOT_ALLOWED_BY_SERVER",
         [6] = "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
         [4] = "INCONSISTENT_FLAGS",
         [1] = "SSL_REQUIRED_BY_SERVER",
         [5] = "HYBRID_REQUIRED_BY_SERVER",
         [3] = "SSL_CERT_NOT_ON_SERVER"
      }


.. bro:id:: RDP::high_color_depths

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [4] = "4bit",
         [24] = "24bit",
         [8] = "8bit",
         [15] = "15bit",
         [16] = "16bit"
      }


.. bro:id:: RDP::languages

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [1129] = "Ibibio - Nigeria",
         [1025] = "Arabic - Saudi Arabia",
         [3073] = "Arabic - Egypt",
         [1084] = "Scottish Gaelic",
         [5121] = "Arabic - Algeria",
         [17417] = "English - Malaysia",
         [1069] = "Basque",
         [1093] = "Bengali (India)",
         [7177] = "English - South Africa",
         [1159] = "Kinyarwanda",
         [2092] = "Azeri (Cyrillic)",
         [1119] = "Tamazight (Arabic)",
         [12297] = "English - Zimbabwe",
         [1121] = "Nepali",
         [1083] = "Sami (Lappish)",
         [1113] = "Sindhi - India",
         [4122] = "Croatian (Bosnia/Herzegovina)",
         [1153] = "Maori - New Zealand",
         [21514] = "Spanish - United States",
         [1026] = "Bulgarian",
         [1041] = "Japanese",
         [2155] = "Quecha - Ecuador",
         [1070] = "Sorbian",
         [1105] = "Tibetan - People's Republic of China",
         [1116] = "Cherokee - United States",
         [1046] = "Portuguese - Brazil",
         [2073] = "Russian - Moldava",
         [2080] = "Urdu - India",
         [1146] = "Mapudungun",
         [1060] = "Slovenian",
         [14346] = "Spanish - Uruguay",
         [1056] = "Urdu",
         [1045] = "Polish",
         [4106] = "Spanish - Guatemala",
         [5146] = "Bosnian (Bosnia/Herzegovina)",
         [1156] = "Alsatian",
         [2070] = "Portuguese - Portugal",
         [1051] = "Slovak",
         [1111] = "Konkani",
         [6153] = "English - Ireland",
         [1101] = "Assamese",
         [10241] = "Arabic - Syria",
         [1095] = "Gujarati",
         [1133] = "Bashkir",
         [1107] = "Khmer",
         [1088] = "Kyrgyz (Cyrillic)",
         [1137] = "Kanuri - Nigeria",
         [11273] = "English - Trinidad",
         [4105] = "English - Canada",
         [7169] = "Arabic - Tunisia",
         [1100] = "Malayalam",
         [1160] = "Wolof",
         [3079] = "German - Austria",
         [1029] = "Czech",
         [1042] = "Korean",
         [1062] = "Latvian",
         [1034] = "Spanish - Spain (Traditional Sort)",
         [1055] = "Turkish",
         [1059] = "Belarusian",
         [1164] = "Dari",
         [13313] = "Arabic - Kuwait",
         [6145] = "Arabic - Morocco",
         [1142] = "Latin",
         [11274] = "Spanish - Argentina",
         [1110] = "Galician",
         [1036] = "French - France",
         [1053] = "Swedish",
         [58380] = "French - North Africa",
         [1104] = "Mongolian (Cyrillic)",
         [2074] = "Serbian (Latin)",
         [13322] = "Spanish - Chile",
         [22538] = "Spanish - Latin America",
         [1128] = "Hausa - Nigeria",
         [1061] = "Estonian",
         [7178] = "Spanish - Dominican Republic",
         [2143] = "Tamazight (Latin)",
         [16385] = "Arabic - Qatar",
         [1067] = "Armenian - Armenia",
         [1065] = "Farsi",
         [2060] = "French - Belgium",
         [1068] = "Azeri (Latin)",
         [1091] = "Uzbek (Latin)",
         [1066] = "Vietnamese",
         [1132] = "Sepedi",
         [6154] = "Spanish - Panama",
         [1058] = "Ukrainian",
         [13321] = "English - Philippines",
         [2064] = "Italian - Switzerland",
         [1141] = "Hawaiian - United States",
         [1038] = "Hungarian",
         [12298] = "Spanish - Ecuador",
         [3179] = "Quecha - Peru\x09CB",
         [10250] = "Spanish - Peru",
         [1124] = "Filipino",
         [1094] = "Punjabi",
         [1115] = "Sinhalese - Sri Lanka",
         [9226] = "Spanish - Colombia",
         [1090] = "Turkmen",
         [2057] = "English - United Kingdom",
         [1122] = "French - West Indies",
         [1117] = "Inuktitut",
         [16393] = "English - India",
         [4100] = "Chinese - Singapore",
         [1043] = "Dutch - Netherlands",
         [15361] = "Arabic - Bahrain",
         [2052] = "Chinese - People's Republic of China",
         [3081] = "English - Australia",
         [2072] = "Romanian - Moldava",
         [11276] = "French - Cameroon",
         [14337] = "Arabic - U.A.E.",
         [1052] = "Albanian - Albania",
         [1063] = "Lithuanian",
         [1086] = "Malay - Malaysia",
         [1047] = "Rhaeto-Romanic",
         [16394] = "Spanish - Bolivia",
         [1028] = "Chinese - Taiwan",
         [1035] = "Finnish",
         [1037] = "Hebrew",
         [1032] = "Greek",
         [1031] = "German - Germany",
         [2110] = "Malay - Brunei Darussalam",
         [1150] = "Breton",
         [1082] = "Maltese",
         [2068] = "Norwegian (Nynorsk)",
         [1138] = "Oromo",
         [1145] = "Papiamentu",
         [1099] = "Kannada",
         [2145] = "Nepali - India",
         [2137] = "Sindhi - Pakistan",
         [18442] = "Spanish - Honduras",
         [1054] = "Thai",
         [1040] = "Italian - Italy",
         [12289] = "Arabic - Lebanon",
         [1123] = "Pashto",
         [1074] = "Tswana",
         [1073] = "Tsonga",
         [1071] = "FYRO Macedonian",
         [1080] = "Faroese",
         [8204] = "French - Reunion",
         [18441] = "English - Singapore",
         [1092] = "Tatar",
         [9225] = "English - Caribbean",
         [11265] = "Arabic - Jordan",
         [1143] = "Somali",
         [1114] = "Syriac",
         [1157] = "Yakut",
         [1127] = "Fulfulde - Nigeria",
         [2049] = "Arabic - Iraq",
         [14345] = "English - Indonesia",
         [2058] = "Spanish - Mexico",
         [1279] = "HID (Human Interface Device)",
         [1057] = "Indonesian",
         [13324] = "French - Mali",
         [1072] = "Sutu",
         [1064] = "Tajik",
         [1079] = "Georgian",
         [1136] = "Igbo - Nigeria",
         [1108] = "Lao",
         [1154] = "Occitan",
         [19466] = "Spanish - Nicaragua",
         [2163] = "Tigrigna - Eritrea",
         [9228] = "French - Democratic Rep. of Congo",
         [3076] = "Chinese - Hong Kong SAR",
         [1076] = "Xhosa",
         [1144] = "Yi",
         [1077] = "Zulu",
         [14348] = "French - Morocco",
         [1140] = "Guarani - Paraguay",
         [1109] = "Burmese",
         [1078] = "Afrikaans - South Africa",
         [5132] = "French - Luxembourg",
         [5129] = "English - New Zealand",
         [2129] = "Tibetan - Bhutan",
         [15369] = "English - Hong Kong SAR",
         [17418] = "Spanish - El Salvador",
         [1027] = "Catalan",
         [2144] = "Kashmiri",
         [1096] = "Oriya",
         [1049] = "Russian",
         [2077] = "Swedish - Finland",
         [2055] = "German - Switzerland",
         [9217] = "Arabic - Yemen",
         [1112] = "Manipuri",
         [2128] = "Mongolian (Mongolian)",
         [2108] = "Irish",
         [12300] = "French - Cote d'Ivoire",
         [1087] = "Kazakh",
         [1098] = "Telugu",
         [4108] = "French - Switzerland",
         [8202] = "Spanish - Venezuela",
         [10249] = "English - Belize",
         [1033] = "English - United States",
         [1120] = "Kashmiri (Arabic)",
         [2115] = "Uzbek (Cyrillic)",
         [1135] = "Greenlandic",
         [20490] = "Spanish - Puerto Rico",
         [1085] = "Yiddish",
         [1126] = "Edo",
         [5127] = "German - Liechtenstein",
         [1102] = "Marathi",
         [1103] = "Sanskrit",
         [2067] = "Dutch - Belgium",
         [1048] = "Romanian",
         [5130] = "Spanish - Costa Rica",
         [8201] = "English - Jamaica",
         [1158] = "K'iche",
         [15370] = "Spanish - Paraguay",
         [1050] = "Croatian",
         [3084] = "French - Canada",
         [8193] = "Arabic - Oman",
         [1081] = "Hindi",
         [1039] = "Icelandic",
         [1148] = "Mohawk",
         [1030] = "Danish",
         [1044] = "Norwegian (Bokmal)",
         [1139] = "Tigrigna - Ethiopia",
         [15372] = "French - Haiti",
         [3098] = "Serbian (Cyrillic)",
         [1075] = "Venda",
         [1118] = "Amharic - Ethiopia",
         [4097] = "Arabic - Libya",
         [1125] = "Divehi",
         [1134] = "Luxembourgish",
         [2118] = "Punjabi (Pakistan)",
         [1089] = "Swahili",
         [1097] = "Tamil",
         [1131] = "Quecha - Bolivia",
         [1106] = "Welsh",
         [1155] = "Corsican",
         [4103] = "German - Luxembourg",
         [5124] = "Chinese - Macao SAR",
         [3082] = "Spanish - Spain (Modern Sort)",
         [10252] = "French - Senegal",
         [1152] = "Uighur - China",
         [6156] = "French - Monaco",
         [7180] = "French - West Indies",
         [1130] = "Yoruba",
         [2117] = "Bengali (Bangladesh)"
      }


.. bro:id:: RDP::results

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "Resources not available",
         [4] = "Locked conference",
         [1] = "User rejected",
         [0] = "Success",
         [3] = "Rejected for symmetry breaking"
      }


.. bro:id:: RDP::security_protocols

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "HYBRID",
         [1] = "SSL",
         [8] = "HYBRID_EX",
         [0] = "RDP"
      }



