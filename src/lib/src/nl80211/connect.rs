// SPDX-License-Identifier: Apache-2.0

// NL80211_CMD_CONNECT / DISCONNECT helpers.
//
// The connection path used by the client is AUTHENTICATE + ASSOCIATE (see
// `auth_assoc.rs`); CONNECT is only used here to tear down a connection.

use futures::TryStreamExt;
use wl_nl80211::Nl80211ConnectionHandle;

use crate::WifiError;

pub async fn disconnect(
    conn_handle: &mut Nl80211ConnectionHandle,
    if_index: u32,
) -> Result<(), WifiError> {
    let attrs = wl_nl80211::Nl80211Disconnect::new(if_index).build();
    let mut stream = conn_handle.disconnect(attrs).execute().await;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}
