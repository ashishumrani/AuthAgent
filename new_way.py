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
def check_supported_org(context: dict) -> {bool,str, str, str, str}:
    # supported_orgs = ["First Bank", "Second Bank", "Tech Corp"]
    # return org_name in supported_orgs
    org_name = context["org_name"]
    print (f"Fetching company record for {org_name}")
    myCompany = Company(org_name)
    myCompany.loadInfo()
    if myCompany.id > 0:
        context["supported"] = True
        context["myCompany"] = myCompany
        return True
    else:
        context["supported"] = False
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

    if oldAuthData.get ("other") is None:
        oldOtherData = {}
    else:
        oldOtherData = oldAuthData.get ("other")

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
        if isinstance(value, str ):
            print( f" New attribute {field} came out ro be string with value {value}")

        if isinstance(value, dict) and value.get("redacted") is not None:
            lines.append(f"- {field.replace('_', ' ').title()}: {value['redacted']}")
        elif isinstance(value, dict) and value.get("raw") is not None:
            lines.append(f"- {field.replace('_', ' ').title()}: {value['raw']}")
        elif value is None:
            # Skip if nothing found
            continue
        else:
            print (f" Variable type is {type(value)}")

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

    return  "\n".join(lines)


def authenticate_user(context,  parsed_data):
    #  Lets send a HTTP request to the server to see if the user is authenticated
    url = context.get("myCompany").authUrl
    response = requests.post(url,
                             json=parsed_data)  # get ("http://10.10.156.21:8080/hello", params = parsed_data)
    try:
        parsed_json = json.loads(response.text)
    except json.JSONDecodeError as e:
        print("Error decoding JSON from model:", e)
        parsed_json = {}

    authScore = parsed_json.get ("authScore")
    parsed_data["authScore"] = authScore

    #  Chceck if the user is authenticated
    if "authenticated" in parsed_json and parsed_json.get("authenticated") == True:
        authLine = "You are authenticated. "
    else:
        authLine = "You are NOT authenticated. "
    print(authLine)
    return authLine


# ----- Agentic Conversational Flow -----
def agentic_conversation(user_input, history, context):
    """
    Handles multi-turn conversation.
    context: stores collected information like 'intent', 'org_name', etc.
    """

    allowedOperations = ["check_balance","transfer_money","deposit","withdraw","open_account","close_account","pay_bill","schedule_payment","stop_payment","locate_branch","report_fraud","currency_exchange","request_statement","loan_inquiry","update_contact","unknown"]

    # Step 1: If intent is not known, ask LLM to detect intent
    if "intent" not in context:
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
        print (response)
        raw_reply = response.choices[0].message.content.strip()
        print (raw_reply)

        try:
            parsed = json.loads(raw_reply)
            # Later on we shall store the complete parsed object in context to check the
            # confidence level etc
            context["intent"] = parsed.get ("operation", "UNKNOWN")
        except json.JSONDecodeError:
            # This is so much hokey pokey.  We need a better way.
            # Fallback: regex to capture `"operation": "something"`
            match = re.search(r'"operation"\s*:\s*"([^"]+)"', raw_reply)
            if match:
                context["intent"] = match.group(1)
            else:
                context["intent"] = "UNKNOWN"

        print (f"Detected intent is {context['intent'] }")


    # if we do not know intent behind the chat then its a simple pleasantory chat.
    if context.get("intent").upper() == "UNKNOWN":
        prompt = """You are a witty bank operator. Assume the user to be fun loving person who has not yet mentioned the operation it wants to perform during this chat.
         Keep replying to the users messages till user mentione operation  to be performed."""

        response = client.chat.completions.create(
            model="gpt-4.1-nano-2025-04-14",
            messages=[{"role": "user", "content": prompt}],
            max_tokens = 2000
        )
        raw_output = response.choices[0].message.content.strip()
        history.append((user_input, raw_output))
        context.pop("intent", None)
        return "", history, context


    # Step 2: If intent is check_balance but no bank_name yet, ask user
    if context.get("intent") in allowedOperations and "org_name" not in context:
        # Try to extract org_name from current message
        # prompt = f"""
        # User message: "{user_input}"
        # If user mentions a bank name, extract it. If not, reply "NONE".
        # """
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
        else:
            # Prompt user to provide bank name
            reply = "That's okay. Can you tell me your bank name?"
            history.append((user_input, reply))
            return "", history, context

    # Step 3: If bank name collected, run internal check
    if  "supported" not in context  and "org_name" in context:
        supported = check_supported_org(context)
        if supported:
            reply = f"Great! We support {context['org_name']}. \n {org_name} allows following operations. \n {context.get('myCompany').supportedOperationsStr}. \n\n\n We accept the following authentication attributes. \n{context.get('myCompany').authAttrStr} \n\n\n {org_name} Typically authenticates you based on {context.get('myCompany').criteriaString}."
        else:
            reply = f"Sorry, we do not support {context['org_name']}."
        history.append((user_input, reply))

        # Return from here does not mke sense.  Why return.  Just continue.
        return "", history, context

    # Now we have collected the intent, name of the org and have verified if we support the org
    # Now its time to collect authentication and verify the user
    if context.get("supported") and context.get("supported") == True:
        # systemPrompt = """
        # You are an extraction assistant. Your job is to parse a single user message and extract authentication-related attributes, returning *only* a single valid JSON object (no surrounding text, no explanation, no markdown).
        #
        # Rules:
        # 1. Output must be valid JSON and nothing else.
        # 2. Look for these attributes (keys) and set them either to a string value or to null if not found:
        #    - account_number
        #    - username
        #    - password
        #    - pin
        #    - zipcode
        #    - phone_number
        #    - card_number
        #    - expiry (for cards; MM/YY or MM/YYYY)
        #    - cvv
        #    - ssn
        #    - email
        #    - other (a list of objects for any additional name/value pairs found)
        # 3. For each found attribute give two subfields:
        #    - raw: the exact substring as found (string)
        #    - redacted: safe redaction following rules below (string)
        #    - confidence: one of "high", "medium", "low" (string)
        #    - indices: [start_index, end_index] in the original user text (character positions). If position can't be determined, use [-1, -1].
        # 4. Redaction rules:
        #    - account_number: keep last 4 digits visible, replace preceding digits with "X" (preserve grouping if possible). Example: "4111 2222 3333 4444" -> "XXXX XXXX XXXX 4444"
        #    - card_number: keep last 4 digits visible, replace preceding digits with "X" (preserve grouping if possible). Example: "4111 2222 3333 4444" -> "XXXX XXXX XXXX 4444"
        #    - password: replace with asterisks of the same length as characters found, except if password length ≤ 4, replace entire string with "****".
        #    - pin: replace all digits with "*" (e.g., "1234" -> "****").
        #    - ssn: show last 4 digits, mask rest: "XXX-XX-1234".
        #    - cvv: replace all digits with "*" (length preserved).
        #    - phone_number: mask middle digits leaving first 2 and last 2 (e.g., "+1-415-555-1234" -> "+1-41*-***-1234" or a similar masked form preserving separators).
        #    - email: mask local-part leaving first and last char: "j*****e@example.com".
        #    - zipcode: keep full zipcode but if it's 9-digit (ZIP+4) mask middle 4 digits: "12345-****".
        #    - address: a string containing street, city, state, and zipcode if present
        #    - other: default to replacing all characters except last 2 with "*" if string length > 2, else "****".
        # 5. Confidence heuristics:
        #    - "high": matches a strict regex for the attribute (see patterns below) and contextual keywords (e.g., "my pin is", "account number:").
        #    - "medium": matches a plausible regex but ambiguous context or formatting (e.g., long numeric string but no label).
        #    - "low": partial matches, natural-language numbers ("one two three four") or guesses.
        # 6. If multiple candidate values are found for a single attribute, return the best candidate in the primary field and list additional candidates under `"other"` as objects like { "name": "account_number", "raw": "...", "redacted": "...", "confidence": "..." }.
        # 7. Always include the original user text in the JSON under `"original_text"`.
        # 8. If nothing is found at all, return all attributes with nulls and an empty `"other": []`.
        # 9. Preserve numeric punctuation (hyphens, spaces) in raw values and use same indices relative to the original text.
        # 10. Do not hallucinate—only extract substrings actually present in the input.
        #
        # All attributes, must be JSON objects with keys "raw", "redacted", "confidence", and "indices". Never output a string or null directly — only objects or null-valued subfields inside objects.
        #
        # Regex references (use these to decide "high" confidence):
        # - account_number / card_number: `\b(?:\d[ -]*?){10,19}\b`
        # - pin: `\b\d{3,6}\b` (label or contextual cue needed for high confidence)
        # - cvv: `\b\d{3,4}\b` (context required)
        # - expiry: `\b(0[1-9]|1[0-2])/(?:\d{2}|\d{4})\b`
        # - zipcode: `\b\d{5}(?:-\d{4})?\b`
        # - phone_number: `\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?)?\d{3}[ -]?\d{4}\b`
        # - ssn: `\b\d{3}-\d{2}-\d{4}\b`
        # - email: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
        # - username: look for words following keywords "username", "user", "login", or patterns `\b[a-zA-Z0-9._-]{3,30}\b` near those keywords.
        # - password: look for words following "password", "pass", "pwd", "secret", or quoted tokens after those labels.
        # Remember: output only JSON. No commentary.
        # """

        systemPrompt = """
            You are an extraction assistant. Your job is to parse a single user message and extract authentication-related attributes, plus address-related details, returning *only* a single valid JSON object (no surrounding text, no explanation, no markdown).
            
            Rules:
            1. Output must be valid JSON and nothing else.
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
                    {"role" : "system", "content": systemPrompt}
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
        authLine = authenticate_user(context, newAuthAttributes)
        collectedAuthInfo = display_auth_info(newAuthAttributes)     #New Attributes, oldAttributes

        context["authAttributes"] = newAuthAttributes

        reply = f"{authLine} \n {collectedAuthInfo} "
        history.append((user_input, reply))
        return "", history, context
    else:
        reply = "Could not collect any information useful for authenticating you.  Can you please provide that information?"
        history.append((user_input, reply))
        return "", history, context

    # Fallback
    reply = "I'm not sure what you want to do."
    history.append(("System", reply))
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
