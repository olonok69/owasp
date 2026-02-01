import re

def security_review_output_guardrail(output):
    
    # get the (JSON) output from the TaskOutput object
    try: 
        json_output = output if isinstance(output, dict) else output.json_dict
    except Exception as e:
        return (False, ("Error retrieving the `json_dict` argument: "
                        f"\n{str(e)}\n"
                        "Make sure you set the output_json parameter in the Task."
                        )
                )

    if json_output is None:
        return (False, "Guardrail received empty output JSON.")

    # define risk levels
    valid_risk_levels = ['low', 'medium', 'high']

    # validate that the highest risk level exists and has a valid value
    highest = json_output.get("highest_risk")
    if not highest or not isinstance(highest, str):
        return (False, "Missing or invalid highest risk level.")
    if highest.lower() not in valid_risk_levels:
        return (False, "Invalid highest risk level.")
    
    # validate that each of the risk levels has a valid value
    for vuln in json_output.get('security_vulnerabilities', []):
        # validate the risk level
        risk_level = vuln.get('risk_level')
        if not risk_level or risk_level.lower() not in valid_risk_levels:
            error_message = f"Invalid risk level: {risk_level}"
            return (False, error_message)
    
    # validate that the highest risk level matches the highest risk level in the vulnerabilities
    # get all risk_level values
    risk_levels = [vuln.get('risk_level', '').lower() for vuln in json_output.get('security_vulnerabilities', []) if vuln.get('risk_level')]
    
    # if "high" in risk levels, then highest risk level should be high
    if "high" in risk_levels: 
        if json_output["highest_risk"].lower() != "high":
            error_message = "Highest risk level does not match the highest risk level in the vulnerabilities."
            return (False, error_message) 
    # if high is not present and medium is in risk levels, then highest risk level should be medium
    elif "medium" in risk_levels: 
        if json_output["highest_risk"].lower() != "medium":
            error_message = "Highest risk level does not match the highest risk level in the vulnerabilities."
            return (False, error_message)
    # if high and medium are not present, then lowest risk level should be low
    elif "low" in risk_levels: 
        if json_output["highest_risk"].lower() != "low":
            error_message = "Highest risk level does not match the highest risk level in the vulnerabilities."
            return (False, error_message)
    return (True, output.json_dict)