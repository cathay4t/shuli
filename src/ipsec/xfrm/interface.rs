// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, time::Duration};

use futures::TryStreamExt;
use rtnetlink::{
    LinkXfrm,
    packet_route::link::{
        InfoData, InfoKind, InfoXfrm, LinkAttribute, LinkInfo,
    },
};

use crate::error::IpsecError;

/// A kernel XFRM interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfrmInterface {
    pub name: String,
    pub if_index: u32,
    pub if_id: u32,
}

pub(crate) async fn query(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<Option<XfrmInterface>, IpsecError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let message = match links.try_next().await {
        Ok(message) => message,
        Err(error) if error.to_string().contains("No such device") => {
            return Ok(None);
        }
        Err(error) => {
            return Err(IpsecError::new(
                crate::error::IpsecErrorKind::Netlink,
                error.to_string(),
            ));
        }
    };
    let Some(message) = message else {
        return Ok(None);
    };
    Ok(parse_interface(&message))
}

pub(crate) async fn create(
    handle: &rtnetlink::Handle,
    name: &str,
    if_id: u32,
    underlay: Option<&str>,
) -> Result<XfrmInterface, IpsecError> {
    let base_name = underlay.unwrap_or("lo");
    let base_index = resolve_index(handle, base_name).await?;
    handle
        .link()
        .add(LinkXfrm::new(name, base_index, if_id).up().build())
        .execute()
        .await
        .map_err(|e| {
            IpsecError::xfrm(format!("create XFRM interface {name}: {e}"))
        })?;

    for _ in 0..20 {
        if let Some(interface) = query(handle, name).await? {
            if interface.if_id == if_id {
                return Ok(interface);
            }
            return Err(IpsecError::xfrm(format!(
                "interface {name} exists with unexpected if_id {}",
                interface.if_id
            )));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(IpsecError::xfrm(format!(
        "XFRM interface {name} did not appear"
    )))
}

pub(crate) async fn delete(
    handle: &rtnetlink::Handle,
    interface: &XfrmInterface,
) -> Result<(), IpsecError> {
    handle
        .link()
        .del(interface.if_index)
        .execute()
        .await
        .map_err(|e| {
            IpsecError::xfrm(format!(
                "delete XFRM interface {}: {e}",
                interface.name
            ))
        })
}

pub(crate) async fn used_if_ids(
    handle: &rtnetlink::Handle,
) -> Result<HashSet<u32>, IpsecError> {
    let mut links = handle.link().get().execute();
    let mut used = HashSet::new();
    while let Some(message) = links.try_next().await.map_err(|e| {
        IpsecError::new(crate::error::IpsecErrorKind::Netlink, e.to_string())
    })? {
        if let Some(interface) = parse_interface(&message) {
            used.insert(interface.if_id);
        }
    }
    Ok(used)
}

async fn resolve_index(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, IpsecError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(message) = links.try_next().await.map_err(|e| {
        IpsecError::new(crate::error::IpsecErrorKind::Netlink, e.to_string())
    })?
    else {
        return Err(IpsecError::xfrm(format!(
            "underlay interface {name} not found"
        )));
    };
    Ok(message.header.index)
}

fn parse_interface(
    message: &rtnetlink::packet_route::link::LinkMessage,
) -> Option<XfrmInterface> {
    let mut name = None;
    let mut if_id = None;
    let mut is_xfrm = false;
    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::IfName(value) => name = Some(value.clone()),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    match info {
                        LinkInfo::Kind(InfoKind::Xfrm) => is_xfrm = true,
                        LinkInfo::Data(InfoData::Xfrm(data)) => {
                            is_xfrm = true;
                            for item in data {
                                if let InfoXfrm::IfId(value) = item {
                                    if_id = Some(*value);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if !is_xfrm {
        return None;
    }
    Some(XfrmInterface {
        name: name?,
        if_index: message.header.index,
        if_id: if_id.unwrap_or(0),
    })
}
