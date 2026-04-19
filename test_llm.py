from llm_connector import ask_llm

system_prompt = "You are a cybersecurity SOC analyst."
user_prompt = "Classify this activity: Multiple connections to 8.8.8.8 from one host."

response = ask_llm(system_prompt, user_prompt)

print("\nLLM Response:\n")
print(response)