// SPDX-License-Identifier: Apache-2.0

/// Build an SAE Authentication frame (commit or confirm).
/// Returns the full 802.11 management frame (without FCS).
/// Frame body format per 802.11-2020 §9.3.3.1.
pub fn build_sae_auth_frame(
    sta_mac: [u8; 6],
    bssid: [u8; 6],
    auth_seq: u16,
    status_code: u16,
    sae_payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + 6 + sae_payload.len());

    // Frame Control: type=mgmt(0x00), subtype=auth(0x0B) = 0x00B0
    frame.extend_from_slice(&0x00B0u16.to_le_bytes());
    // Duration
    frame.extend_from_slice(&0x0000u16.to_le_bytes());
    // DA = BSSID
    frame.extend_from_slice(&bssid);
    // SA = STA MAC
    frame.extend_from_slice(&sta_mac);
    // BSSID
    frame.extend_from_slice(&bssid);
    // Seq Ctrl
    frame.extend_from_slice(&0x0000u16.to_le_bytes());

    // Frame body: Auth Algorithm = SAE (3). 802.11 fixed fields are
    // little-endian.
    frame.extend_from_slice(&3u16.to_le_bytes());
    // Auth Seq (1 = commit, 2 = confirm)
    frame.extend_from_slice(&auth_seq.to_le_bytes());
    // Status Code
    frame.extend_from_slice(&status_code.to_le_bytes());
    // SAE payload
    frame.extend_from_slice(sae_payload);

    frame
}

/// Parse an SAE Authentication frame from a full 802.11 mgmt frame.
/// Returns (auth_seq, status_code, sae_payload).
pub fn parse_sae_auth_frame(full_frame: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
    if full_frame.len() < 30 {
        return None;
    }
    let fc = u16::from_le_bytes([full_frame[0], full_frame[1]]);
    if fc & 0x00FC != 0x00B0 {
        return None;
    }
    let body = &full_frame[24..];
    if body.len() < 6 {
        return None;
    }
    let auth_alg = u16::from_le_bytes([body[0], body[1]]);
    if auth_alg != 3 {
        return None;
    }
    let auth_seq = u16::from_le_bytes([body[2], body[3]]);
    let status_code = u16::from_le_bytes([body[4], body[5]]);
    let sae_payload = body[6..].to_vec();
    Some((auth_seq, status_code, sae_payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sae_commit_frame() {
        let sta = [0x02u8; 6];
        let ap = [0x01u8; 6];
        let payload = b"0123456789abcdef0123456789abcdef".to_vec();
        let frame = build_sae_auth_frame(sta, ap, 1, 0, &payload);
        assert!(frame.len() > 24);
        let parsed = parse_sae_auth_frame(&frame);
        assert!(parsed.is_some());
        let (seq, status, pl) = parsed.unwrap();
        assert_eq!(seq, 1);
        assert_eq!(status, 0);
        assert_eq!(pl, payload);
    }

    #[test]
    fn parse_wrong_auth_alg() {
        let frame = build_sae_auth_frame([0u8; 6], [0u8; 6], 1, 0, &[]);
        // Change auth algorithm to non-SAE
        let mut modified = frame.clone();
        modified[24] = 0;
        modified[25] = 1;
        assert!(parse_sae_auth_frame(&modified).is_none());
    }

    #[test]
    fn parse_too_short() {
        assert!(parse_sae_auth_frame(&[0u8; 10]).is_none());
    }
}
