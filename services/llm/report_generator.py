from langchain_ollama import ChatOllama

llm = ChatOllama(model="phi3", temperature=0.2)

def generate_org_report(org_name, pages):

    if not pages:
        return "No data found"

    combined = "\n\n".join(pages)[:6000]

    prompt = f"""
You are a cyber threat intelligence analyst.

Analyze dark web data related to {org_name}.

Generate a professional threat report:

1. Overall threat summary
2. Is organization at risk?
3. Types of threats found
4. Any credential leaks
5. Most serious finding
6. Final risk level (CRITICAL/HIGH/MEDIUM/LOW)
7. Recommended actions

Dark web data:
{combined}
"""

    try:
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        print("LLM error:", e)
        return "Report generation failed"