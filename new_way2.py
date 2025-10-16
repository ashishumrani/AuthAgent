import json

import gradio as gr
from openai import OpenAI
from dotenv import load_dotenv
import re

load_dotenv(override=True)
from company import Company
import requests

client = OpenAI()


# ----- Internal Tools -----
def check_supported_org(context: dict) -> {bool, str, str, str, str}:
    # supported_orgs = ["First Bank", "Second Bank", "Tech Corp"]
    # return org_name in supported_orgs
    org_name = context["org_name"]
    print(f"Fetching company record for {org_name}")
    myCompany = Company(org_name)
    myCompany.loadInfo()
    if myCompany.id > 0:
        context["orgSupported"] = True
        context["myCompany"] = myCompany
        return True
    else:
        context["orgSupported"] = False
        return False


def copy_auth_info(newAuthData: dict, oldAuthData: dict):
    """
    This function will merge the new entered data with the old data.
    Always new data will take precedence over the old data.
    """
    # Fields we want to show in a nice order
    fields = [
        "account_number", "username", "password", "pin", "zipcode",
        "phone_number", "card_number", "expiry", "cvv", "ssn", "email"
    ]

    if oldAuthData is None:
        oldAuthData = {}

    if oldAuthData.get("other") is None:
        oldOtherData = {}
    else:
        oldOtherData = oldAuthData.get("other")

    for field in fields:
        value = newAuthData.get(field)
        oldvalue = oldAuthData.get(field)

        if value is None:
            # copy old value is its present
            if oldvalue is not None:
                newAuthData[field] = oldvalue
                value = oldvalue

    # Handle extra attributes if present
    other = newAuthData.get("other", {})

    for item in oldOtherData:
        if isinstance(item, dict):
            name = item.get("name", "unknown")
            # redacted = item.get("redacted", "****")
            if name not in other:
                # This means there was no such entry in old dict
                # so copy it
                other[name] = item


def display_auth_info(newAuthData: dict) -> str:
    """
    Display user authentication info in a safe, user-friendly way.
    Uses the 'redacted' values for sensitive fields.
    """
    # Fields we want to show in a nice order
    fields = [
        "account_number", "username", "password", "pin", "zipcode",
        "phone_number", "card_number", "expiry", "cvv", "ssn", "email"
    ]

    lines = []
    lines.append("Here’s the authentication information I detected (redacted for safety):\n")

    for field in fields:
        value = newAuthData.get(field)
        if isinstance(value, str):
            print(f" New attribute {field} came out ro be string with value {value}")

        if isinstance(value, dict) and value.get("redacted") is not None:
            lines.append(f"- {field.replace('_', ' ').title()}: {value['redacted']}")
        elif isinstance(value, dict) and value.get("raw") is not None:
            lines.append(f"- {field.replace('_', ' ').title()}: {value['raw']}")
        elif value is None:
            # Skip if nothing found
            continue
        else:
            print(f" Variable type is {type(value)}")

    # Handle extra attributes if present
    other = newAuthData.get("other", [])
    if other:
        lines.append("\nOther detected attributes:")
        for item in other:
            if isinstance(item, dict):
                name = item.get("name", "unknown")
                redacted = item.get("redacted", "****")
                lines.append(f"- {name.title()}: {redacted}")

    # Handling of auth score
    lines.append(f"Authentication Score: {newAuthData.get('authScore')}")

    return "\n".join(lines)


def authenticate_user(context, parsed_data):
    #  Lets send a HTTP request to the server to see if the user is authenticated
    url = context.get("myCompany").authUrl
    response = requests.post(url,
                             json=parsed_data)  # get ("http://10.10.156.21:8080/hello", params = parsed_data)
    try:
        parsed_json = json.loads(response.text)
    except json.JSONDecodeError as e:
        print("Error decoding JSON from model:", e)
        parsed_json = {}

    authScore = parsed_json.get("authScore")
    parsed_data["authScore"] = authScore

    #  Chceck if the user is authenticated
    if "authenticated" in parsed_json and parsed_json.get("authenticated") == True:
        authLine = "You are authenticated. "
        context ["userAuthenticated"] = True
        context["authScore"] = authScore
    else:
        authLine = "You are NOT authenticated. "
        context ["userAuthenticated"] = False
    print(authLine)
    return authLine


# ----- Agentic Conversational Flow -----
def agentic_conversation(user_input, history, context):
    """
    Handles multi-turn conversation.
    context: stores collected information like 'intent', 'org_name', etc.
    """

    allowedOperations = ["check_balance", "transfer_money", "deposit", "withdraw", "open_account", "close_account",
                         "pay_bill", "schedule_payment", "stop_payment", "locate_branch", "report_fraud",
                         "currency_exchange", "request_statement", "loan_inquiry", "update_contact", "unknown"]

    # -----------------
    # Step 0   Initializing the context
    # -----------------
    if "intentDetected" not in context:
        context["intentDetected"] = False
    if "orgDetected" not in context:
        context["orgDetected"] = False
    if "orgSupported" not in context:
        context["orgSupported"] = False

    # -----------------
    # Step 1: Detect the intent
    # -----------------
    prompt = f"""
    User message: "{user_input}"        
    You are a bank-operation detector. Given a user's raw message above, return a JSON object that identifies the most likely banking operation (intent), any extracted entities, and a confidence score between 0.0 and 1.0.
    Rules:
    1. Only return JSON and nothing else.
    2. The "operation" must be one of the canonical labels in "operations" (see examples).
    3. Put extracted entities in "entities" as key->value pairs.
    4. Confidence must be a float with two decimal places (e.g., 0.87).
    5. If the message is ambiguous or non-banking, set operation to "unknown" and provide a short "explain" field.
    6. Do not hallucinate account numbers or sensitive data; extract only what is explicitly present.

    Canonical operations: 
    {allowedOperations}
    """

    response = client.chat.completions.create(
        model="gpt-4.1-nano-2025-04-14",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000,
        response_format={"type": "json_object"}
    )
    raw_reply = response.choices[0].message.content.strip()
    try:
        parsed = json.loads(raw_reply)
        # Later on we shall store the complete parsed object in context to check the
        # confidence level etc
        intent = parsed.get("operation", "UNKNOWN")
        if intent.upper().strip() != "UNKNOWN":
            context["intent"] = intent
            context["intentDetected"] = True
        else:
            # check if the intent was detected as a part of previous input
            # if not then only mark it as unknown
            if not context["intentDetected"]:
                context["intent"] = "UNKNOWN"
                context["intentDetected"] = False

    except json.JSONDecodeError:
        # This is so much hokey pokey.  We need a better way.
        # Fallback: regex to capture `"operation": "something"`
        match = re.search(r'"operation"\s*:\s*"([^"]+)"', raw_reply)
        if match:
            context["intent"] = match.group(1)
            context["intentDetected"] = True
        else:
            if not context["intentDetected"]:
                context["intent"] = "UNKNOWN"
                context["intentDetected"] = False

    print(f"Detected intent is {context['intent']}")

    # -----------------
    # Step 2: Detect the Org
    # -----------------
    prompt = f"""
    You are an information extraction assistant.  
    Extract the name of the organization from the following user message.  
    If the name starts with an article like "a","an" or "The", remove it unless the article is part of the company’s official legal name.  
    Return only the normalized organization name as plain text.  
    If no name can be concluded then return "NONE"

    User message: "{user_input}"        
    """
    response = client.chat.completions.create(
        model="gpt-4.1-nano-2025-04-14",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2000
    )
    org_name = response.choices[0].message.content.strip()
    if org_name != "NONE":
        context["org_name"] = org_name
        context["orgDetected"] = True
    else:
        # Prompt user to provide bank name
        if not context["orgDetected"]:
            context["orgDetected"] = False
            context["org_name"] = "NONE"

    print(f"Detected org is {context['org_name']}")


    # -----------------
    # Step 3: check if the operation specified is supported by the org not
    # -----------------
    if context["orgDetected"] and  context['org_name'] != "NONE":
        supported = check_supported_org(context)
        if supported:
            # TBD  hardcoding the auth level for the operation as of this moment.  We will read it from db in next few days
            context ["authLevelRequired"] = 120


    # -----------------
    # Step 4: collect all auth attributes
    # -----------------
    systemPrompt = """
        You are an extraction assistant. Your job is to parse a single user message and extract authentication-related attributes, plus address-related details, returning *only* a single valid JSON object (no surrounding text, no explanation, no markdown).

        Rules:
        1. Output must be valid JSON and nothing else. All numbers in the output (including indices) must use numeric form, not words.
        2. Look for these attributes (keys) and set them either to a structured object or to null if not found:
           - account_number
           - username
           - password
           - pin
           - zipcode
           - phone_number
           - card_number
           - expiry (for cards; MM/YY or MM/YYYY)
           - cvv
           - ssn
           - email
           - address (a nested object with fields for street, city, state, zipcode)
           - other (a list of objects for any additional name/value pairs found)

        3. Each attribute (including subfields) must have:
           - raw: the exact substring as found (string)
           - redacted: safe redaction following rules below (string)
           - confidence: one of "high", "medium", or "low" (string)
           - indices: [start_index, end_index] in the original user text (character positions). If not determinable, use [-1, -1].

        4. Redaction rules:
           - account_number / card_number: keep last 4 digits visible, replace preceding digits with "X" (preserve grouping).
           - password: replace with asterisks of the same length, or "****" if ≤4 chars.
           - pin: replace all digits with "*".
           - ssn: show last 4 digits, mask rest ("XXX-XX-1234").
           - cvv: replace all digits with "*".
           - phone_number: mask middle digits, leaving first 2 and last 2 visible.
           - email: mask local-part leaving first and last char visible.
           - zipcode: keep full ZIP unless ZIP+4; in that case, mask last 4 digits as "****".
           - address subfields (street, city, state): redact only if explicitly sensitive; otherwise keep as-is.
           - other: mask all but last 2 characters.

        5. Confidence heuristics:
           - "high": matches strict regex + clear context.
           - "medium": plausible pattern, ambiguous context.
           - "low": weak cues or partial matches.

        6. Address detection heuristic (progressive approach):
           1. Look for a valid ZIP code using `\b\d{5}(?:-\d{4})?\b`.
           2. If found, look immediately before it for a two-letter uppercase token → interpret as `state` (`\b[A-Z]{2}\b`).
           3. The preceding token(s) (letters/spaces) form the `city` name.
           4. Text before the city that starts with a number and street-like words → interpret as `street`.
              Example heuristic: `\b\d{1,6}\s+[A-Za-z0-9 .#'-]+`
           5. If all four components (street, city, state, zipcode) are found, confidence = "high".
              If only 3 are found, confidence = "medium".
              If fewer, "low".
           6. Combine into a single `"address"` object with subfields: street, city, state, zipcode.
           7. Include an overall `"address"` field summarizing the full string (concatenation of subfields).

        7. Regex references for authentication-related attributes:
           - account_number / card_number: `\b(?:\d[ -]*?){10,19}\b`
           - pin: `\b\d{3,6}\b`
           - cvv: `\b\d{3,4}\b`
           - expiry: `\b(0[1-9]|1[0-2])/(?:\d{2}|\d{4})\b`
           - zipcode: `\b\d{5}(?:-\d{4})?\b`
           - phone_number: `\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?)?\d{3}[ -]?\d{4}\b`
           - ssn: `\b\d{3}-\d{2}-\d{4}\b`
           - email: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
           - username: look for keywords "username", "user", "login" or pattern `\b[a-zA-Z0-9._-]{3,30}\b`
           - password: look for words following "password", "pass", "pwd", "secret", or quoted tokens after those labels.

        8. Always include `"original_text"` in the JSON output (the full user input).

        9. If nothing is found, return all attributes (and subfields) with `null` and `"other": []`.

        10. Do not hallucinate or infer values that do not appear verbatim in the input text.

        11. All attributes, and subfields must be JSON objects with keys "raw", "redacted", "confidence", and "indices". Never output a string or null directly — only objects or null-valued subfields inside objects

    """
    userPrompt = f"""
    Extract authentication attributes from the following text and return a JSON object according to the system rules.
    User message: "{user_input}"
    """

    response = client.chat.completions.create(
        model="gpt-4.1-nano-2025-04-14",
        messages=[
            {"role": "user", "content": userPrompt},
            {"role": "system", "content": systemPrompt}
        ],
        max_tokens=2000
    )

    raw_output = response.choices[0].message.content.strip()
    try:
        newAuthAttributes = json.loads(raw_output)
    except json.JSONDecodeError as e:
        print("Error decoding JSON from model:", e)
        newAuthAttributes = {}

    copy_auth_info(newAuthAttributes, context.get("authAttributes"))

    # If org is specified then authenticate the user
    if context["orgSupported"]:
        #  Further optimization is possible.  Check
        # if the username is specified or not TBD
        authLine = authenticate_user(context, newAuthAttributes)

    collectedAuthInfo = display_auth_info(newAuthAttributes)  # New Attributes, oldAttributes
    context["collectedAuthInfo"] = collectedAuthInfo

    # Add the auth attributes even if the user remains un authenticated
    context["authAttributes"] = newAuthAttributes

    # reply = f"{collectedAuthInfo} "
    # history.append((user_input, reply))
    # return "", history, context
    print(f"Detected Auth attributes are {context['collectedAuthInfo']}")

    # ----------------------
    # Step 5 Sum it up
    # ----------------------
    if not context["intentDetected"]:
        if not context["orgDetected"]:
            # Ask for intent and org
            prompt = """You are a witty bank operator. Assume the user to be fun loving person who has not yet mentioned the operation and organization. Prompt the user for the same"""

            response = client.chat.completions.create(
                model="gpt-4.1-nano-2025-04-14",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000
            )
            raw_output = response.choices[0].message.content.strip()
            history.append((user_input, raw_output))
            # context.pop("intent", None)
            return "", history, context
        else:
            if not context["orgSupported"]:
                reply = f"Great! We support {context['org_name']}. \n " \
                        f"{context['org_name']} allows following operations. \n " \
                        f"{context.get('myCompany').supportedOperationsStr}. \n\n\n " \
                        f"We accept the following authentication attributes. \n{context.get('myCompany').authAttrStr} \n\n\n " \
                        f"{context['org_name']} Typically authenticates you based on {context.get('myCompany').criteriaString}."
            else:
                reply = f"""Unfortunately we do not support {context["org_name"]} at this time. """
    else:
        if not context["orgDetected"]:
            # this means we have intent but no org
            # so ask for the org
            reply = f"""Sure we can help you do {context["intent"]}.  Can you tell me organization you work with? """
        else:
            # This means we have intent and org
            if context["orgSupported"]:
                # We have intent and or, as wella s verified that org is supported
                # TBD check the operation based on organization
                if context["intent"] in allowedOperations:
                    # this means the intent is supported too
                    if "userAuthenticated" in context and context["userAuthenticated"]:
                        # User is authenticated too
                        if context["authLevelRequired"] < context ["authScore"]:
                            # SUCCESS
                            reply = f""" GREAT JOB.\n\n\n You are authenticated for {context["intent"]}  with {context["org_name"]}. \n  Auth level required {context["authLevelRequired"]} auth points and you have {context["authScore"]}  points. \n\n\n I will forward you to appropriate agent now"""
                        else:
                            reply = f""" We need to further verify your identity. \n\n\n You are authenticated for {context["intent"]}  with {context["org_name"]}. \n  Auth level required {context["authLevelRequired"]} auth points and you have {context["authScore"]}  points. \n We have collected the following auth info \n {collectedAuthInfo}\\n\nn {org_name} accepts the following authentication attributes for this purpose. \n{context.get('myCompany').authAttrStr} \n\n\n """
                    else:
                        # user is un authenticated
                        reply = f"Great! We support {context['org_name']}. \n {context['org_name']} allows following operations. \n " \
                                f"{context.get('myCompany').supportedOperationsStr}. \n\n\n " \
                                f"We accept the following authentication attributes. \n{context.get('myCompany').authAttrStr} \n\n\n " \
                                f"{context['org_name']} Typically authenticates you based on {context.get('myCompany').criteriaString}."

                else:
                    # org is supported but invalid intent
                    reply = f"""unfortunately this operation is not permitted at this time. {org_name} allows following operations. \n\n\n {context.get('myCompany').supportedOperationsStr}. \n\n\n """
            else:
                # org is not supported
                reply = f"""Unfortunately we do not support {context["org_name"]} """


    history.append((user_input, reply))
    return "", history, context


# ----- Gradio UI -----
with gr.Blocks() as demo:
    chatbot = gr.Chatbot(
        value=[("", "👋 Hello! How can I help you today?")],  # initial message
        label="Assistant")
    user_input = gr.Textbox(label="Your message")
    submit_btn = gr.Button("Send")

    # Use a dictionary to persist context per session
    state = gr.State(value={})


    def gr_submit(user_msg, chat_history, context):
        response, updated_history, updated_context = agentic_conversation(
            user_msg, chat_history or [], context
        )
        return "", updated_history, updated_context


    submit_btn.click(
        gr_submit,
        inputs=[user_input, chatbot, state],
        outputs=[user_input, chatbot, state]
    )

demo.launch()
