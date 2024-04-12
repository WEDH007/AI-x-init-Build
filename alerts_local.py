import smtplib
import os
from datetime import datetime
from flask import Flask,request
from flask_cors import CORS
from dotenv import load_dotenv
from twilio.rest import Client
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)
CORS(app)


# limiter = Limiter(
#     app=app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )


@app.route("/",methods=['GET'])
def hello_world():
    return "Hello World",201

@app.route("/api/alerts",methods=['POST'])
#@limiter.limit("5 per minute")
def receive_alert():
    data = request.json
    
    process_alert_and_notify(data)
    
    return "Alert processed", 200


def send_email(recipients, subject, body):
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login("aiprojectalert02@gmail.com", os.getenv("APP_PASSWORD"))
            smtp.sendmail("aiprojectalert02@gmail.com", recipients, f"Subject: {subject}\n\n{body}")
            smtp.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")

def send_sms(number_to_send,body):
    account_sid = os.getenv("ACCOUNT_SID")
    auth_token = os.getenv("AUTH_TOKEN")
    client = Client(account_sid,auth_token)

    message = client.messages.create(
        body=body,
        from_="+18888937469",
        to=number_to_send
    )
    print(message.sid)



def process_alert_and_notify(alert_data):
    attack = alert_data.get("attack")
    precision = alert_data.get("probability")
    date = alert_data.get("date")
    src_ip = alert_data.get("src_ip")


    attack_date = datetime.fromisoformat(date).strftime('%Y-%m-%d %H:%M:%S')
    
    message = f"URGENT: A new attack ({attack}) was detected on {attack_date} with a precision of {precision} from {src_ip}. Immediate action required."
    email_recipients = [
        # "wissamhassani15@gmail.com", 
        # "wissamamin@gmail.com",
        # "nicholas.cogua@hotmail.com",
        'williamenrique2001@gmail.com'
    ]
    
    # phone_numbers = ['+17862941983', '+17864988923', '+17542778833', '+14087685538']

    # Send email notifications
    for recipient in email_recipients:
        send_email(recipient, "Security Alert", message)

    # Send SMS notifications
    #for number in phone_numbers:
        #send_sms(number, message)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
