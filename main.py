import gradio as gr
from openai import OpenAI
from dotenv import load_dotenv
from company import Company
from agents import Agent, Runner, trace, function_tool

# Load environment variables
load_dotenv(override=True)


# Initialize OpenAI client (make sure you have OPENAI_API_KEY set in your environment)
client = OpenAI()

@function_tool
def check_bank(
        bankName: str
):
    """
    Check if we support banking for this organization.
    Also tells what credentials are required.
    Returns a list of dictionaries.
    """
    myCompany = Company(bankName)
    myCompany.loadInfo()
    if myCompany.id > 0:
        return {"supported": True, "required_fields": myCompany.uniqueCriteria}
    else:
        return {"supported": False, "required_fields": []}

@function_tool
def authenticate_user(
    userName: str = None,
    password: str = None,
    cardNumber: str = None,
    pin: str = None
):
    """
    Authenticate the user using either username/password or cardNumber/pin.
    Returns True if authentication succeeds, False otherwise.
    Inform tha user whether user is authenticated or not
    """

    print ("In authenticate user")
    if userName == "ashish" and password == "123456":
        print ("Authenticated 1")
        return {"authenticated": True, "method": "username_password"}

    if cardNumber == "1234123412345678" and pin == "12345":
        print ("Authenticated 2")
        return {"authenticated": True, "method": "card_pin"}

    return {"authenticated": False, "method": None,"next": "handle_failed_auth"}


@function_tool
def handle_failed_auth(
        bankName: str,
        attempted_userName: str = None,
        attempted_cardNumber: str = None
):
    """
    Handles failed authentication attempts.
    Returns a message prompting the user to retry credentials.
    """
    print ("In handle_failed_auth")
    message = f"Authentication failed for bank '{bankName}'."

    if attempted_userName:
        message += f" Username '{attempted_userName}' is incorrect."
    elif attempted_cardNumber:
        message += f" Card Number '{attempted_cardNumber}' is incorrect."

    message += " Please re-enter your credentials."

    return {"message": message, "next": "authenticate_user"}

# Build the agent
agent = Agent(
    name="BankAssistant",
    instructions=(
        "You are a witty assistant to help customer do banking operations. "
        "Answer clearly and concisely. For any banking operation the customer needs to be authenticated. "
        "Each bank has unique way of authenticating user. One needs to start by mentioning the name of the bank "
        "that one works with to see if we support that bank. Use check_bank tool to see if we support that bank. Use authenticate_user tool to authenticate a user,"
        " Use handle_failed_auth tool to inform the user if the authentication has failed."
        "if the user is authenticated then inform the user of being authenticated, otherwise clearly mention that authentication has failed"
    ),
    tools=[check_bank, authenticate_user, handle_failed_auth],
    model="gpt-4.1-nano-2025-04-14"   # choose the valid model
)


# Chat function
async def chat_with_gpt(message, history):
    # You may need to format history properly for the Agent input
    # openai-agents usually takes just the messages or past inputs
    # For instance:
    prompt = message
    # If you want history, you might give it context to the agent, or configure memory
    result = await Runner.run(agent, input=prompt)
    bot_reply = result.final_output

    # If tool calls were made, you can inspect result.tool_calls etc
    # For example:
    # if result.tool_calls:
    #     ... handle them; maybe integrate their outputs in the reply

    history.append((message, bot_reply))
    return "", history


# Define the function
def clear_chat():
    """
    Clears the chatbot messages and the textbox input.
    Returns an empty conversation and empty string.
    """
    return [], ""   # First goes to chatbot, second to textbox

# Gradio UI
with gr.Blocks() as demo:
    gr.Markdown("## 💬 ChatGPT Gradio Demo")

    chatbot = gr.Chatbot()
    msg = gr.Textbox(label="Your message")
    clear = gr.Button("Clear")

    # input to the following function represents a callback functiona_name, input parameters and Output parameters
    # Thats just FYI
    msg.submit(chat_with_gpt, [msg, chatbot], [msg, chatbot])

    # clear.click(lambda: None, None, chatbot, queue=False)
    clear.click(
        fn=clear_chat,
        inputs=None,          # no inputs needed
        outputs=[chatbot, msg]
    )

# Launch
if __name__ == "__main__":
    demo.launch()
