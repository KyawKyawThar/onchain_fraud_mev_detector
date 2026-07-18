//! [`MultiChannelSink`] — the production [`ChannelSink`]: dispatches each
//! `(notice, channel)` pair to the right adapter (`http_delivery` for
//! webhook/Slack/PagerDuty, `email_delivery` for SMTP). The one place that
//! knows all four [`Channel`] variants exist, so a fifth channel is a
//! compile error here, not a silent no-op.

use async_trait::async_trait;

use crate::delivery::{ChannelSink, DeliveryError};
use crate::email_delivery::EmailDelivery;
use crate::http_delivery::HttpDelivery;
use crate::model::Channel;
use crate::notice::Notice;

pub struct MultiChannelSink {
    http: HttpDelivery,
    email: EmailDelivery,
}

impl MultiChannelSink {
    pub fn new(http: HttpDelivery, email: EmailDelivery) -> Self {
        Self { http, email }
    }
}

#[async_trait]
impl ChannelSink for MultiChannelSink {
    async fn deliver(&self, notice: &Notice, channel: &Channel) -> Result<(), DeliveryError> {
        match channel {
            Channel::Webhook { url } => self.http.deliver_webhook(notice, url).await,
            Channel::Slack { webhook_url } => self.http.deliver_slack(notice, webhook_url).await,
            Channel::PagerDuty { routing_key } => {
                self.http.deliver_pagerduty(notice, routing_key).await
            }
            Channel::Email { address } => self.email.deliver_email(notice, address).await,
        }
    }
}
