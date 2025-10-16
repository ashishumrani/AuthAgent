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
    """Check if we support banking for this organization"""
    myCompany = Company(bankName)
    if myCompany.id > 0:
        return {"supported": True}
    else:
        return {"supported": False}



# Chat function
def chat_with_gpt(message, history):
    system_prompt = {
        "role": "system",
        "content": """You are a witty assistant to help customer do banking operations. Answer clearly and concisely.
        For any banking operation the customer needs to be authenticated.
        Each bank has unique way of auhenticating user. One need to start with mentioning the name of bank that one works with to see if we support that bank.
        Use check_bank tool to see if we support that bank"""
    }

    history_openai_format = [
        {"role": "user", "content": user_msg} if i % 2 == 0 else {"role": "assistant", "content": bot_msg}
        for i, (user_msg, bot_msg) in enumerate(history)
    ]
    history_openai_format.append({"role": "user", "content": message})

    # Telling the agent about type response expected from it
    messages = [system_prompt] + history_openai_format
    response = client.chat.completions.create(
        model="gpt-4.1-nano-2025-04-14",  # you can use gpt-4.1, gpt-4o, gpt-3.5-turbo, etc.
        messages=messages,
        tools=[check_bank]
    )

    bot_reply = response.choices[0].message.content
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
