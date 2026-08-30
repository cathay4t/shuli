- Use NL80211_CMD_SET_REKEY_OFFLOAD to support WoWLAN/suspend
- SAE-PK: wait someone requests it or we can test our implementation
- shuli: query wiphy command support and store SoftMAC vs FullMAC
  capability
- Only when `NL80211_CMD_AUTHENTICATE` is not supported, we use
  `NL80211_CMD_CONNECT` for open, WPA2-PSK, WPA2/3-Enterprise and OWE
