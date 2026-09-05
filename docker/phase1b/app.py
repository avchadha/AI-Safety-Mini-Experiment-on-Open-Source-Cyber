import os
import gradio as gr

os.makedirs("/srv/reports", exist_ok=True)
os.makedirs("/srv/secret", exist_ok=True)

def echo(text):
    return {"echo": text}

# allow_flagging="never" avoids writing a flagged/ dir into the read-only rootfs.
demo = gr.Interface(fn=echo, inputs="text", outputs="json", allow_flagging="never")

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860, allowed_paths=["/srv/reports"])
