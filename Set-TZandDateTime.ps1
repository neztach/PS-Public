[CmdletBinding()]
Param ([switch]$test)
$test = $true
 
$tzList = @{
    ### Abbrv as you see fit
    ### REF: https://powers-hell.azurewebsites.net/2020/08/31/setting-the-time-zone-of-an-intune-managed-device-using-azure-maps-powershell/
    'Africa/Abidjan'                                                    = 'Greenwich Standard Time'
    'Africa/Accra'                                                      = 'Greenwich Standard Time'
    'Africa/Addis_Ababa'                                                = 'E. Africa Standard Time'
    'Africa/Algiers'                                                    = 'W. Central Africa Standard Time'
    'Africa/Asmera'                                                     = 'E. Africa Standard Time'
    'Africa/Bamako'                                                     = 'Greenwich Standard Time'
    'Africa/Bangui'                                                     = 'W. Central Africa Standard Time'
    'Africa/Banjul'                                                     = 'Greenwich Standard Time'
    'Africa/Bissau'                                                     = 'Greenwich Standard Time'
    'Africa/Blantyre'                                                   = 'South Africa Standard Time'
    'Africa/Brazzaville'                                                = 'W. Central Africa Standard Time'
    'Africa/Bujumbura'                                                  = 'South Africa Standard Time'
    'Africa/Cairo'                                                      = 'Egypt Standard Time'
    'Africa/Casablanca'                                                 = 'Morocco Standard Time'
    'Africa/Conakry'                                                    = 'Greenwich Standard Time'
    'Africa/Dakar'                                                      = 'Greenwich Standard Time'
    'Africa/Dar_es_Salaam'                                              = 'E. Africa Standard Time'
    'Africa/Djibouti'                                                   = 'E. Africa Standard Time'
    'Africa/Douala'                                                     = 'W. Central Africa Standard Time'
    'Africa/El_Aaiun'                                                   = 'Morocco Standard Time'
    'Africa/Freetown'                                                   = 'Greenwich Standard Time'
    'Africa/Gaborone'                                                   = 'South Africa Standard Time'
    'Africa/Harare'                                                     = 'South Africa Standard Time'
    'Africa/Johannesburg'                                               = 'South Africa Standard Time'
    'Africa/Juba'                                                       = 'E. Africa Standard Time'
    'Africa/Kampala'                                                    = 'E. Africa Standard Time'
    'Africa/Khartoum'                                                   = 'E. Africa Standard Time'
    'Africa/Kigali'                                                     = 'South Africa Standard Time'
    'Africa/Kinshasa'                                                   = 'W. Central Africa Standard Time'
    'Africa/Lagos'                                                      = 'W. Central Africa Standard Time'
    'Africa/Libreville'                                                 = 'W. Central Africa Standard Time'
    'Africa/Lome'                                                       = 'Greenwich Standard Time'
    'Africa/Luanda'                                                     = 'W. Central Africa Standard Time'
    'Africa/Lubumbashi'                                                 = 'South Africa Standard Time'
    'Africa/Lusaka'                                                     = 'South Africa Standard Time'
    'Africa/Malabo'                                                     = 'W. Central Africa Standard Time'
    'Africa/Maputo'                                                     = 'South Africa Standard Time'
    'Africa/Maseru'                                                     = 'South Africa Standard Time'
    'Africa/Mbabane'                                                    = 'South Africa Standard Time'
    'Africa/Mogadishu'                                                  = 'E. Africa Standard Time'
    'Africa/Monrovia'                                                   = 'Greenwich Standard Time'
    'Africa/Nairobi'                                                    = 'E. Africa Standard Time'
    'Africa/Ndjamena'                                                   = 'W. Central Africa Standard Time'
    'Africa/Niamey'                                                     = 'W. Central Africa Standard Time'
    'Africa/Nouakchott'                                                 = 'Greenwich Standard Time'
    'Africa/Ouagadougou'                                                = 'Greenwich Standard Time'
    'Africa/Porto-Novo'                                                 = 'W. Central Africa Standard Time'
    'Africa/Sao_Tome'                                                   = 'Greenwich Standard Time'
    'Africa/Tripoli'                                                    = 'Libya Standard Time'
    'Africa/Tunis'                                                      = 'W. Central Africa Standard Time'
    'Africa/Windhoek'                                                   = 'Namibia Standard Time'
    'America/Anchorage'                                                 = 'Alaskan Standard Time'
    'America/Anchorage America/Juneau America/Nome America/Sitka America/Yakutat' = 'Alaskan Standard Time'
    'America/Anguilla'                                                  = 'SA Western Standard Time'
    'America/Antigua'                                                   = 'SA Western Standard Time'
    'America/Aruba'                                                     = 'SA Western Standard Time'
    'America/Asuncion'                                                  = 'Paraguay Standard Time'
    'America/Bahia'                                                     = 'Bahia Standard Time'
    'America/Barbados'                                                  = 'SA Western Standard Time'
    'America/Belize'                                                    = 'Central America Standard Time'
    'America/Blanc-Sablon'                                              = 'SA Western Standard Time'
    'America/Bogota'                                                    = 'SA Pacific Standard Time'
    'America/Buenos_Aires'                                              = 'Argentina Standard Time'
    'America/Buenos_Aires America/Argentina/La_Rioja America/Argentina/Rio_Gallegos America/Argentina/Salta America/Argentina/San_Juan America/Argentina/San_Luis America/Argentina/Tucuman America/Argentina/Ushuaia America/Catamarca America/Cordoba America/Jujuy America/Mendoza' = 'Argentina Standard Time'
    'America/Caracas'                                                   = 'Venezuela Standard Time'
    'America/Cayenne'                                                   = 'SA Eastern Standard Time'
    'America/Cayman'                                                    = 'SA Pacific Standard Time'
    'America/Chicago'                                                   = 'Central Standard Time'
    'America/Chicago America/Indiana/Knox America/Indiana/Tell_City America/Menominee America/North_Dakota/Beulah America/North_Dakota/Center America/North_Dakota/New_Salem' = 'Central Standard Time'
    'America/Chihuahua'                                                 = 'Mountain Standard Time (Mexico)'
    'America/Chihuahua America/Mazatlan'                                = 'Mountain Standard Time (Mexico)'
    'America/Coral_Harbour'                                             = 'SA Pacific Standard Time'
    'America/Costa_Rica'                                                = 'Central America Standard Time'
    'America/Cuiaba'                                                    = 'Central Brazilian Standard Time'
    'America/Cuiaba America/Campo_Grande'                               = 'Central Brazilian Standard Time'
    'America/Curacao'                                                   = 'SA Western Standard Time'
    'America/Danmarkshavn'                                              = 'UTC'
    'America/Dawson_Creek America/Creston'                              = 'US Mountain Standard Time'
    'America/Denver'                                                    = 'Mountain Standard Time'
    'America/Denver America/Boise America/Shiprock'                     = 'Mountain Standard Time'
    'America/Dominica'                                                  = 'SA Western Standard Time'
    'America/Edmonton America/Cambridge_Bay America/Inuvik America/Yellowknife' = 'Mountain Standard Time'
    'America/El_Salvador'                                               = 'Central America Standard Time'
    'America/Fortaleza America/Araguaina America/Belem America/Maceio America/Recife America/Santarem' = 'SA Eastern Standard Time'
    'America/Godthab'                                                   = 'Greenland Standard Time'
    'America/Grand_Turk'                                                = 'Eastern Standard Time'
    'America/Grenada'                                                   = 'SA Western Standard Time'
    'America/Guadeloupe'                                                = 'SA Western Standard Time'
    'America/Guatemala'                                                 = 'Central America Standard Time'
    'America/Guayaquil'                                                 = 'SA Pacific Standard Time'
    'America/Guyana'                                                    = 'SA Western Standard Time'
    'America/Halifax'                                                   = 'Atlantic Standard Time'
    'America/Halifax America/Glace_Bay America/Goose_Bay America/Moncton' = 'Atlantic Standard Time'
    'America/Havana'                                                    = 'Eastern Standard Time'
    'America/Hermosillo'                                                = 'US Mountain Standard Time'
    'America/Indianapolis'                                              = 'US Eastern Standard Time'
    'America/Indianapolis America/Indiana/Marengo America/Indiana/Vevay' = 'US Eastern Standard Time'
    'America/Jamaica'                                                   = 'SA Pacific Standard Time'
    'America/Kralendijk'                                                = 'SA Western Standard Time'
    'America/La_Paz'                                                    = 'SA Western Standard Time'
    'America/Lima'                                                      = 'SA Pacific Standard Time'
    'America/Los_Angeles'                                               = 'Pacific Standard Time'
    'America/Lower_Princes'                                             = 'SA Western Standard Time'
    'America/Managua'                                                   = 'Central America Standard Time'
    'America/Manaus America/Boa_Vista America/Porto_Velho'              = 'SA Western Standard Time'
    'America/Marigot'                                                   = 'SA Western Standard Time'
    'America/Martinique'                                                = 'SA Western Standard Time'
    'America/Matamoros'                                                 = 'Central Standard Time'
    'America/Mexico_City'                                               = 'Central Standard Time (Mexico)'
    'America/Mexico_City America/Bahia_Banderas America/Cancun America/Merida America/Monterrey' = 'Central Standard Time (Mexico)'
    'America/Montevideo'                                                = 'Montevideo Standard Time'
    'America/Montserrat'                                                = 'SA Western Standard Time'
    'America/Nassau'                                                    = 'Eastern Standard Time'
    'America/New_York'                                                  = 'Eastern Standard Time'
    'America/New_York America/Detroit America/Indiana/Petersburg America/Indiana/Vincennes America/Indiana/Winamac America/Kentucky/Monticello America/Louisville' = 'Eastern Standard Time'
    'America/Noronha'                                                   = 'UTC-02'
    'America/Ojinaga'                                                   = 'Mountain Standard Time'
    'America/Panama'                                                    = 'SA Pacific Standard Time'
    'America/Paramaribo'                                                = 'SA Eastern Standard Time'
    'America/Phoenix'                                                   = 'US Mountain Standard Time'
    'America/Port-au-Prince'                                            = 'Eastern Standard Time'
    'America/Port_of_Spain'                                             = 'SA Western Standard Time'
    'America/Puerto_Rico'                                               = 'SA Western Standard Time'
    'America/Regina'                                                    = 'Canada Central Standard Time'
    'America/Regina America/Swift_Current'                              = 'Canada Central Standard Time'
    'America/Rio_Branco America/Eirunepe'                               = 'SA Pacific Standard Time'
    'America/Santa_Isabel'                                              = 'Pacific Standard Time (Mexico)'
    'America/Santiago'                                                  = 'Pacific SA Standard Time'
    'America/Santo_Domingo'                                             = 'SA Western Standard Time'
    'America/Sao_Paulo'                                                 = 'E. South America Standard Time'
    'America/Scoresbysund'                                              = 'Azores Standard Time'
    'America/St_Barthelemy'                                             = 'SA Western Standard Time'
    'America/St_Johns'                                                  = 'Newfoundland Standard Time'
    'America/St_Kitts'                                                  = 'SA Western Standard Time'
    'America/St_Lucia'                                                  = 'SA Western Standard Time'
    'America/St_Thomas'                                                 = 'SA Western Standard Time'
    'America/St_Vincent'                                                = 'SA Western Standard Time'
    'America/Tegucigalpa'                                               = 'Central America Standard Time'
    'America/Thule'                                                     = 'Atlantic Standard Time'
    'America/Tijuana'                                                   = 'Pacific Standard Time'
    'America/Toronto America/Iqaluit America/Montreal America/Nipigon America/Pangnirtung America/Thunder_Bay' = 'Eastern Standard Time'
    'America/Tortola'                                                   = 'SA Western Standard Time'
    'America/Vancouver America/Dawson America/Whitehorse'               = 'Pacific Standard Time'
    'America/Winnipeg America/Rainy_River America/Rankin_Inlet America/Resolute' = 'Central Standard Time'
    'Antarctica/Casey'                                                  = 'W. Australia Standard Time'
    'Antarctica/Davis'                                                  = 'SE Asia Standard Time'
    'Antarctica/DumontDUrville'                                         = 'West Pacific Standard Time'
    'Antarctica/Macquarie'                                              = 'Central Pacific Standard Time'
    'Antarctica/Mawson'                                                 = 'West Asia Standard Time'
    'Antarctica/McMurdo'                                                = 'New Zealand Standard Time'
    'Antarctica/Palmer'                                                 = 'Pacific SA Standard Time'
    'Antarctica/Rothera'                                                = 'SA Eastern Standard Time'
    'Antarctica/Syowa'                                                  = 'E. Africa Standard Time'
    'Antarctica/Vostok'                                                 = 'Central Asia Standard Time'
    'Arctic/Longyearbyen'                                               = 'W. Europe Standard Time'
    'Asia/Aden'                                                         = 'Arab Standard Time'
    'Asia/Almaty'                                                       = 'Central Asia Standard Time'
    'Asia/Almaty Asia/Qyzylorda'                                        = 'Central Asia Standard Time'
    'Asia/Amman'                                                        = 'Jordan Standard Time'
    'Asia/Ashgabat'                                                     = 'West Asia Standard Time'
    'Asia/Baghdad'                                                      = 'Arabic Standard Time'
    'Asia/Bahrain'                                                      = 'Arab Standard Time'
    'Asia/Baku'                                                         = 'Azerbaijan Standard Time'
    'Asia/Bangkok'                                                      = 'SE Asia Standard Time'
    'Asia/Beirut'                                                       = 'Middle East Standard Time'
    'Asia/Bishkek'                                                      = 'Central Asia Standard Time'
    'Asia/Brunei'                                                       = 'Singapore Standard Time'
    'Asia/Calcutta'                                                     = 'India Standard Time'
    'Asia/Colombo'                                                      = 'Sri Lanka Standard Time'
    'Asia/Damascus'                                                     = 'Syria Standard Time'
    'Asia/Dhaka'                                                        = 'Bangladesh Standard Time'
    'Asia/Dili'                                                         = 'Tokyo Standard Time'
    'Asia/Dubai'                                                        = 'Arabian Standard Time'
    'Asia/Dushanbe'                                                     = 'West Asia Standard Time'
    'Asia/Hong_Kong'                                                    = 'China Standard Time'
    'Asia/Hovd'                                                         = 'SE Asia Standard Time'
    'Asia/Irkutsk'                                                      = 'North Asia East Standard Time'
    'Asia/Jakarta Asia/Pontianak'                                       = 'SE Asia Standard Time'
    'Asia/Jayapura'                                                     = 'Tokyo Standard Time'
    'Asia/Jerusalem'                                                    = 'Israel Standard Time'
    'Asia/Kabul'                                                        = 'Afghanistan Standard Time'
    'Asia/Karachi'                                                      = 'Pakistan Standard Time'
    'Asia/Katmandu'                                                     = 'Nepal Standard Time'
    'Asia/Krasnoyarsk'                                                  = 'North Asia Standard Time'
    'Asia/Kuala_Lumpur Asia/Kuching'                                    = 'Singapore Standard Time'
    'Asia/Kuwait'                                                       = 'Arab Standard Time'
    'Asia/Macau'                                                        = 'China Standard Time'
    'Asia/Magadan'                                                      = 'Magadan Standard Time'
    'Asia/Magadan Asia/Anadyr Asia/Kamchatka'                           = 'Magadan Standard Time'
    'Asia/Makassar'                                                     = 'Singapore Standard Time'
    'Asia/Manila'                                                       = 'Singapore Standard Time'
    'Asia/Muscat'                                                       = 'Arabian Standard Time'
    'Asia/Nicosia'                                                      = 'GTB Standard Time'
    'Asia/Novosibirsk'                                                  = 'N. Central Asia Standard Time'
    'Asia/Novosibirsk Asia/Novokuznetsk Asia/Omsk'                      = 'N. Central Asia Standard Time'
    'Asia/Oral Asia/Aqtau Asia/Aqtobe'                                  = 'West Asia Standard Time'
    'Asia/Phnom_Penh'                                                   = 'SE Asia Standard Time'
    'Asia/Pyongyang'                                                    = 'Korea Standard Time'
    'Asia/Qatar'                                                        = 'Arab Standard Time'
    'Asia/Rangoon'                                                      = 'Myanmar Standard Time'
    'Asia/Riyadh'                                                       = 'Arab Standard Time'
    'Asia/Saigon'                                                       = 'SE Asia Standard Time'
    'Asia/Seoul'                                                        = 'Korea Standard Time'
    'Asia/Shanghai'                                                     = 'China Standard Time'
    'Asia/Shanghai Asia/Chongqing Asia/Harbin Asia/Kashgar Asia/Urumqi' = 'China Standard Time'
    'Asia/Singapore'                                                    = 'Singapore Standard Time'
    'Asia/Taipei'                                                       = 'Taipei Standard Time'
    'Asia/Tashkent'                                                     = 'West Asia Standard Time'
    'Asia/Tashkent Asia/Samarkand'                                      = 'West Asia Standard Time'
    'Asia/Tbilisi'                                                      = 'Georgian Standard Time'
    'Asia/Tehran'                                                       = 'Iran Standard Time'
    'Asia/Thimphu'                                                      = 'Bangladesh Standard Time'
    'Asia/Tokyo'                                                        = 'Tokyo Standard Time'
    'Asia/Ulaanbaatar'                                                  = 'Ulaanbaatar Standard Time'
    'Asia/Ulaanbaatar Asia/Choibalsan'                                  = 'Ulaanbaatar Standard Time'
    'Asia/Vientiane'                                                    = 'SE Asia Standard Time'
    'Asia/Vladivostok'                                                  = 'Vladivostok Standard Time'
    'Asia/Vladivostok Asia/Sakhalin Asia/Ust-Nera'                      = 'Vladivostok Standard Time'
    'Asia/Yakutsk'                                                      = 'Yakutsk Standard Time'
    'Asia/Yakutsk Asia/Khandyga'                                        = 'Yakutsk Standard Time'
    'Asia/Yekaterinburg'                                                = 'Ekaterinburg Standard Time'
    'Asia/Yerevan'                                                      = 'Caucasus Standard Time'
    'Atlantic/Azores'                                                   = 'Azores Standard Time'
    'Atlantic/Bermuda'                                                  = 'Atlantic Standard Time'
    'Atlantic/Canary'                                                   = 'GMT Standard Time'
    'Atlantic/Cape_Verde'                                               = 'Cape Verde Standard Time'
    'Atlantic/Faeroe'                                                   = 'GMT Standard Time'
    'Atlantic/Reykjavik'                                                = 'Greenwich Standard Time'
    'Atlantic/South_Georgia'                                            = 'UTC-02'
    'Atlantic/Stanley'                                                  = 'SA Eastern Standard Time'
    'Atlantic/St_Helena'                                                = 'Greenwich Standard Time'
    'Australia/Adelaide'                                                = 'Cen. Australia Standard Time'
    'Australia/Adelaide Australia/Broken_Hill'                          = 'Cen. Australia Standard Time'
    'Australia/Brisbane'                                                = 'E. Australia Standard Time'
    'Australia/Brisbane Australia/Lindeman'                             = 'E. Australia Standard Time'
    'Australia/Darwin'                                                  = 'AUS Central Standard Time'
    'Australia/Hobart'                                                  = 'Tasmania Standard Time'
    'Australia/Hobart Australia/Currie'                                 = 'Tasmania Standard Time'
    'Australia/Perth'                                                   = 'W. Australia Standard Time'
    'Australia/Sydney'                                                  = 'AUS Eastern Standard Time'
    'Australia/Sydney Australia/Melbourne'                              = 'AUS Eastern Standard Time'
    'CST6CDT'                                                           = 'Central Standard Time'
    'EST5EDT'                                                           = 'Eastern Standard Time'
    'Etc/GMT'                                                           = 'UTC'
    'Etc/GMT+1'                                                         = 'Cape Verde Standard Time'
    'Etc/GMT+10'                                                        = 'Hawaiian Standard Time'
    'Etc/GMT+11'                                                        = 'UTC-11'
    'Etc/GMT+12'                                                        = 'Dateline Standard Time'
    'Etc/GMT+2'                                                         = 'UTC-02'
    'Etc/GMT+3'                                                         = 'SA Eastern Standard Time'
    'Etc/GMT+4'                                                         = 'SA Western Standard Time'
    'Etc/GMT+5'                                                         = 'SA Pacific Standard Time'
    'Etc/GMT+6'                                                         = 'Central America Standard Time'
    'Etc/GMT+7'                                                         = 'US Mountain Standard Time'
    'Etc/GMT-1'                                                         = 'W. Central Africa Standard Time'
    'Etc/GMT-10'                                                        = 'West Pacific Standard Time'
    'Etc/GMT-11'                                                        = 'Central Pacific Standard Time'
    'Etc/GMT-12'                                                        = 'UTC+12'
    'Etc/GMT-13'                                                        = 'Tonga Standard Time'
    'Etc/GMT-2'                                                         = 'South Africa Standard Time'
    'Etc/GMT-3'                                                         = 'E. Africa Standard Time'
    'Etc/GMT-4'                                                         = 'Arabian Standard Time'
    'Etc/GMT-5'                                                         = 'West Asia Standard Time'
    'Etc/GMT-6'                                                         = 'Central Asia Standard Time'
    'Etc/GMT-7'                                                         = 'SE Asia Standard Time'
    'Etc/GMT-8'                                                         = 'Singapore Standard Time'
    'Etc/GMT-9'                                                         = 'Tokyo Standard Time'
    'Europe/Amsterdam'                                                  = 'W. Europe Standard Time'
    'Europe/Andorra'                                                    = 'W. Europe Standard Time'
    'Europe/Athens'                                                     = 'GTB Standard Time'
    'Europe/Belgrade'                                                   = 'Central Europe Standard Time'
    'Europe/Berlin'                                                     = 'W. Europe Standard Time'
    'Europe/Berlin Europe/Busingen'                                     = 'W. Europe Standard Time'
    'Europe/Bratislava'                                                 = 'Central Europe Standard Time'
    'Europe/Brussels'                                                   = 'Romance Standard Time'
    'Europe/Bucharest'                                                  = 'GTB Standard Time'
    'Europe/Budapest'                                                   = 'Central Europe Standard Time'
    'Europe/Chisinau'                                                   = 'GTB Standard Time'
    'Europe/Copenhagen'                                                 = 'Romance Standard Time'
    'Europe/Dublin'                                                     = 'GMT Standard Time'
    'Europe/Gibraltar'                                                  = 'W. Europe Standard Time'
    'Europe/Guernsey'                                                   = 'GMT Standard Time'
    'Europe/Helsinki'                                                   = 'FLE Standard Time'
    'Europe/Isle_of_Man'                                                = 'GMT Standard Time'
    'Europe/Istanbul'                                                   = 'Turkey Standard Time'
    'Europe/Jersey'                                                     = 'GMT Standard Time'
    'Europe/Kaliningrad'                                                = 'Kaliningrad Standard Time'
    'Europe/Kiev'                                                       = 'FLE Standard Time'
    'Europe/Kiev Europe/Simferopol Europe/Uzhgorod Europe/Zaporozhye'   = 'FLE Standard Time'
    'Europe/Lisbon Atlantic/Madeira'                                    = 'GMT Standard Time'
    'Europe/Ljubljana'                                                  = 'Central Europe Standard Time'
    'Europe/London'                                                     = 'GMT Standard Time'
    'Europe/Luxembourg'                                                 = 'W. Europe Standard Time'
    'Europe/Madrid Africa/Ceuta'                                        = 'Romance Standard Time'
    'Europe/Malta'                                                      = 'W. Europe Standard Time'
    'Europe/Mariehamn'                                                  = 'FLE Standard Time'
    'Europe/Minsk'                                                      = 'Kaliningrad Standard Time'
    'Europe/Monaco'                                                     = 'W. Europe Standard Time'
    'Europe/Moscow'                                                     = 'Russian Standard Time'
    'Europe/Moscow Europe/Samara Europe/Volgograd'                      = 'Russian Standard Time'
    'Europe/Oslo'                                                       = 'W. Europe Standard Time'
    'Europe/Paris'                                                      = 'Romance Standard Time'
    'Europe/Podgorica'                                                  = 'Central Europe Standard Time'
    'Europe/Prague'                                                     = 'Central Europe Standard Time'
    'Europe/Riga'                                                       = 'FLE Standard Time'
    'Europe/Rome'                                                       = 'W. Europe Standard Time'
    'Europe/San_Marino'                                                 = 'W. Europe Standard Time'
    'Europe/Sarajevo'                                                   = 'Central European Standard Time'
    'Europe/Skopje'                                                     = 'Central European Standard Time'
    'Europe/Sofia'                                                      = 'FLE Standard Time'
    'Europe/Stockholm'                                                  = 'W. Europe Standard Time'
    'Europe/Tallinn'                                                    = 'FLE Standard Time'
    'Europe/Tirane'                                                     = 'Central Europe Standard Time'
    'Europe/Vaduz'                                                      = 'W. Europe Standard Time'
    'Europe/Vatican'                                                    = 'W. Europe Standard Time'
    'Europe/Vienna'                                                     = 'W. Europe Standard Time'
    'Europe/Vilnius'                                                    = 'FLE Standard Time'
    'Europe/Warsaw'                                                     = 'Central European Standard Time'
    'Europe/Zagreb'                                                     = 'Central European Standard Time'
    'Europe/Zurich'                                                     = 'W. Europe Standard Time'
    'Indian/Antananarivo'                                               = 'E. Africa Standard Time'
    'Indian/Chagos'                                                     = 'Central Asia Standard Time'
    'Indian/Christmas'                                                  = 'SE Asia Standard Time'
    'Indian/Cocos'                                                      = 'Myanmar Standard Time'
    'Indian/Comoro'                                                     = 'E. Africa Standard Time'
    'Indian/Kerguelen'                                                  = 'West Asia Standard Time'
    'Indian/Mahe'                                                       = 'Mauritius Standard Time'
    'Indian/Maldives'                                                   = 'West Asia Standard Time'
    'Indian/Mauritius'                                                  = 'Mauritius Standard Time'
    'Indian/Mayotte'                                                    = 'E. Africa Standard Time'
    'Indian/Reunion'                                                    = 'Mauritius Standard Time'
    'MST7MDT'                                                           = 'Mountain Standard Time'
    'Pacific/Apia'                                                      = 'Samoa Standard Time'
    'Pacific/Auckland'                                                  = 'New Zealand Standard Time'
    'Pacific/Auckland Antarctica/South_Pole'                            = 'New Zealand Standard Time'
    'Pacific/Efate'                                                     = 'Central Pacific Standard Time'
    'Pacific/Enderbury'                                                 = 'Tonga Standard Time'
    'Pacific/Fakaofo'                                                   = 'Tonga Standard Time'
    'Pacific/Fiji'                                                      = 'Fiji Standard Time'
    'Pacific/Funafuti'                                                  = 'UTC+12'
    'Pacific/Galapagos'                                                 = 'Central America Standard Time'
    'Pacific/Guadalcanal'                                               = 'Central Pacific Standard Time'
    'Pacific/Guam'                                                      = 'West Pacific Standard Time'
    'Pacific/Honolulu'                                                  = 'Hawaiian Standard Time'
    'Pacific/Johnston'                                                  = 'Hawaiian Standard Time'
    'Pacific/Majuro Pacific/Kwajalein'                                  = 'UTC+12'
    'Pacific/Midway'                                                    = 'UTC-11'
    'Pacific/Nauru'                                                     = 'UTC+12'
    'Pacific/Niue'                                                      = 'UTC-11'
    'Pacific/Noumea'                                                    = 'Central Pacific Standard Time'
    'Pacific/Pago_Pago'                                                 = 'UTC-11'
    'Pacific/Palau'                                                     = 'Tokyo Standard Time'
    'Pacific/Ponape Pacific/Kosrae'                                     = 'Central Pacific Standard Time'
    'Pacific/Port_Moresby'                                              = 'West Pacific Standard Time'
    'Pacific/Rarotonga'                                                 = 'Hawaiian Standard Time'
    'Pacific/Saipan'                                                    = 'West Pacific Standard Time'
    'Pacific/Tahiti'                                                    = 'Hawaiian Standard Time'
    'Pacific/Tarawa'                                                    = 'UTC+12'
    'Pacific/Tongatapu'                                                 = 'Tonga Standard Time'
    'Pacific/Truk'                                                      = 'West Pacific Standard Time'
    'Pacific/Wake'                                                      = 'UTC+12'
    'Pacific/Wallis'                                                    = 'UTC+12'
    'PST8PDT'                                                           = 'Pacific Standard Time'
}
 
#region Functions
Function Get-tzAbbreviation {
    <#
        .SYNOPSIS
        Gets Time Zone abbreviation from worldtimeapi.org.
        .DESCRIPTION
        Gets Time Zone abbreviation from worldtimeapi.org.
        .EXAMPLE
        Get-tzAbbreviation
        .INPUTS
        None.
        .OUTPUTS
        String.
    #>
    Try {
        $webData = Invoke-WebRequest -Uri 'https://worldtimeapi.org/api/ip' -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        $Content = ConvertFrom-Json -InputObject $webData.Content
        Return $($Content.timezone)
    } Catch {
        Throw 'Get-tzAbbreviation Failed'
    }
}
 
Function Get-AtomicTime     {
    <#
        .SYNOPSIS
        Gets current time from the Atomic Clock.
        .DESCRIPTION
        Gets current time from the Atomic Clock.
        .PARAMETER TimeServer
        Define what timeserver to query - default is http://time.nist.gov:13.
        .PARAMETER NoCache
        Do not use cached resolution - query time zerver fresh.
        .EXAMPLE
        Get-AtomicTime
        .INPUTS
        URI.
        .OUTPUTS
        datetime.
    #>
    [CmdletBinding()] 
    Param (
        [string]$TimeServer = 'http://time.nist.gov:13', 
        [bool]$NoCache = $false
    )
    If ($NoCache -eq $true) {
        $rand   = New-Object -TypeName System.Random 
        $unique = $rand.nextdouble()
    }
    trap {
        return 'No Time Returned From ' + $TimeServer
        continue
    }
    $URL        = $TimeServer + '?_' + $unique
    $xHTTP      = New-Object -COM msxml2.xmlhttp
    $xHTTP.open('GET', $URL, $false)
    $xHTTP.send()
    $response   = $xHTTP.ResponseText
    $timeString = $response.substring(10, 2) + '/' + $response.substring(13, 2) + '/' + $response.substring(7, 2) + ' ' + $response.substring(16, 9)
    $timezone   = Get-WmiObject -Class Win32_TimeZone
    $bias       = $timezone.bias
    Return ([datetime]$timeString).addminutes($bias)
}
#endregion Functions
 
#region Colors
$C   = 'Cyan'
$Y   = 'Yellow'
$Ye  = @{ForegroundColor = $Y}
$Re  = @{ForegroundColor = 'Red'}
$nCy = @{
    NoNewLine = $true
    ForegroundColor = $C
}
#endregion Colors
 
If (Test-Connection -Computer google.com -Count 1 -Quiet) {
    ### External IP
    #(Invoke-WebRequest ifconfig.me/ip).Content.Trim()
 
    ### TimeZone
    $tz        = Get-tzAbbreviation
    $windowsId = $tzList.Get_Item($tz)
    If ($windowsId) {
        $result = $windowsId
    } Else {
        $result = ($tzList.GetEnumerator() | Where-Object {$_.Key -like "*$($tz)*"}).Value
    }
    Write-Host 'Setting timezone to : ' @nCy
    Write-Host "$result" @Ye
    If (-not $test) {
        Set-TimeZone -Id $result
    }
 
    ### Atomic Time
    $Atomic = Get-AtomicTime
    Write-Host 'Setting time to     : ' @nCy
    Write-Host $Atomic @Ye
    If (-not $test) {
        Set-Date -Date $Atomic
    }
} Else {
    Write-Host 'No Internet connection...' @Re
}
