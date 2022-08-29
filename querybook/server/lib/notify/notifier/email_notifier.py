import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from env import QuerybookSettings
from lib.notify.base_notifier import BaseNotifier
from lib.logger import get_logger

LOG = get_logger(__file__)


class EmailNotifier(BaseNotifier):
    @property
    def notifier_name(self):
        return "email"

    @property
    def notifier_format(self):
        return "html"

    def notify(self, user, message):
        from_email = QuerybookSettings.MAIL_DEFAULT_SENDER
        subject = message.split("\n")[0]
        message = self._convert_markdown(message)
        try:
            date = datetime.now().strftime("%a, %d %b %Y")

            msg = MIMEMultipart()
            msg["Subject"] = subject
            msg["Date"] = date
            msg["From"] = from_email
            msg["To"] = user.email
            msg.attach(MIMEText(message, "html"))
            LOG.debug(f"Deliver email ({subject}) to {user.email}; from: {from_email}")
            # LOG.debug(f"MAIL_PASSWORD: {QuerybookSettings.MAIL_PASSWORD}")

            smtp = smtplib.SMTP(
                QuerybookSettings.MAIL_SERVER, QuerybookSettings.MAIL_PORT
            )
            if QuerybookSettings.MAIL_USE_SSL:
                smtp = smtplib.SMTP_SSL(
                    QuerybookSettings.MAIL_SERVER, QuerybookSettings.MAIL_PORT
                )
            if QuerybookSettings.MAIL_USE_TLS:
                smtp.starttls()

            smtp.login(QuerybookSettings.MAIL_USERNAME, QuerybookSettings.MAIL_PASSWORD)
            smtp.sendmail(msg["From"], msg["To"], msg.as_string())
            smtp.quit()
        except Exception as e:
            LOG.errof("*** failed to send email ***")
            LOG.error(e)
