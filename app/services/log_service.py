import re
from sqlalchemy.orm import Session
from app.models.log import LogEntry
from datetime import datetime


DELIMITERS = [
    "0035AUG", "0035BUZ", "0035CUL", "0035CUM", "0035CUN", "0035CUO", "0035CUP",
    "0035CUY", "0035EU3", "0035FU2", "0035FUA", "0035FU1", "0035AUE", "0035AUF",
    "0035AUG", "0035AUH", "0035AUI", "0035AUJ", "0035EU1", "0035EU2", "0035EU5",
    "0035FU0", "0035FUB"
]

DELIMITER_PATTERN = re.compile(r"(" + "|".join(DELIMITERS) + r")")

MESSAGE_TEMPLATES = {
    "BUZ": {"audit_class": "Other Events", "message_severity": "High", "message_text": "> in program &A, line &B, event &C"},
    "CUL": {"audit_class": "Other Events", "message_severity": "High", "message_text": "Field content in debugger changed by user &A(&B): &C (&D)"},
    "CUM": {"audit_class": "Other Events", "message_severity": "High", "message_text": "Jump to ABAP Debugger by user &A(&B): &C (&D)"},
    "CUN": {"audit_class": "Other Events", "message_severity": "High", "message_text": "A process was stopped from the debugger by user &A(&B) (&D)"},
    "CUO": {"audit_class": "Other Events", "message_severity": "High", "message_text": "Explicit database operation in debugger by user &A(&B): &C (&D)"},
    "CUP": {"audit_class": "Other Events", "message_severity": "High", "message_text": "Non-exclusive debugging session started by user &A(&B) (&D)"},
    "CUY": {"audit_class": "Other Events", "message_severity": "Low", "message_text": "> &A"},
    "EU3": {"audit_class": "Other Events", "message_severity": "High", "message_text": "&A change documents deleted without archiving (&B)"},
    "FU2": {"audit_class": "Other Events", "message_severity": "Medium", "message_text": "Parsing of an XML data stream canceled for security reasons (reason = &A)"},
    "FUA": {"audit_class": "Other Events", "message_severity": "High", "message_text": "Audit alert: &A | &B &C &D"},
    "FU1": {"audit_class": "RFC Function Call", "message_severity": "Low", "message_text": "RFC function &B with dynamic destination &C was called in program &A"},
    "AUE": {"audit_class": "System Events", "message_severity": "High", "message_text": "Audit configuration changed"},
    "AUF": {"audit_class": "System Events", "message_severity": "High", "message_text": "Audit: Slot &A: Class &B, Severity &C, User &D, Client &E, &F"},
    "AUG": {"audit_class": "System Events", "message_severity": "High", "message_text": "Application server started"},
    "AUH": {"audit_class": "System Events", "message_severity": "High", "message_text": "Application server stopped"},
    "AUI": {"audit_class": "System Events", "message_severity": "High", "message_text": "Audit: Slot &A Inactive"},
    "AUJ": {"audit_class": "System Events", "message_severity": "High", "message_text": "Audit: Active status set to &1"},
    "EU1": {"audit_class": "System Events", "message_severity": "High", "message_text": "System changeability changed (&A to &B)"},
    "EU2": {"audit_class": "System Events", "message_severity": "High", "message_text": "Client setting for &A changed (&B)"},
    "EU5": {"audit_class": "System Events", "message_severity": "Low", "message_text": "Audit log data of &A was deleted (&B data records)"},
    "FU0": {"audit_class": "System Events", "message_severity": "High", "message_text": "Exclusive security audit log medium changed (new status &A)"},
    "FUB": {"audit_class": "System Events", "message_severity": "High", "message_text": "TEMP: Customer-specific event FUB &A &B &C &D"}
}

def format_date_time(raw_date, raw_time):
   formatted_date = f"{raw_date[:4]}-{raw_date[4:6]}-{raw_date[6:]}"
   time_obj = datetime.strptime(raw_time, "%H%M%S") 
   formatted_time = time_obj.strftime("%I:%M:%S %p") 
   return formatted_date, formatted_time

def format_message(template: str, first: str, second: str, third: str, extra: str = "") -> str:
    return template.replace("&A", first).replace("&B", second).replace("&C", third).replace("&D", extra)



def extract_variable_length_field(data: str, start_idx: int):    
    field_length_str = data[start_idx:start_idx + 4]
    print(f"Extracted raw field length: '{field_length_str}' at position {start_idx}")

    try:
        field_length = int(field_length_str)
    except ValueError:
        raise ValueError(f"Invalid field length: '{field_length_str}' at position {start_idx} in data: '{data[start_idx:start_idx+20]}'")
    if start_idx + 4 + field_length > len(data):
        print(f"Warning: Field length {field_length} exceeds available data length. Skipping data.")
        return "", start_idx + 4 

    field_value = data[start_idx + 4:start_idx + 4 + field_length]
    return field_value, start_idx + 4 + field_length


def process_aud_file(file_path: str):
    with open(file_path, "r") as f:
        content = f.read()

    
    trimmed_content = content[101:]
    segments = re.split(DELIMITER_PATTERN, trimmed_content)

    parsed_segments = []
    for i in range(1, len(segments), 2):
        full_delimiter = segments[i]
        data = segments[i + 1] if i + 1 < len(segments) else ""
        first_4_chars = full_delimiter[:4]
        last_3_chars = full_delimiter[4:]

        adjusted_data = last_3_chars + data.strip()
        parsed_segments.append((first_4_chars, adjusted_data))
    print("hello", parsed_segments)


    return parsed_segments
        
     

def parse_log_data(parsed_segments):
    parsed_logs = []  
    for delimiter, data in parsed_segments:
        message_identifier = data[:3]  
        message_template = MESSAGE_TEMPLATES.get(message_identifier) 
        raw_date = data[3:11]  
        raw_time = data[11:17] 

        formatted_date, formatted_time = format_date_time(raw_date, raw_time)
        
        parsed_data = {
            "sap_system_id": "S4H",
            "app_server_instance": "vhcals4hci_S4H_00",
            "message_identifier": message_identifier,
            "syslog_msg_group": data[:2],
            "sub_name": data[2:3],
            "date":formatted_date,
            "time": formatted_time,
            "operating_system_number": data[19:24],
            "work_process_number": data[24:29],
            "sap_process": data[29:31],
            "client": data[31:34],
            "file_number": data[34:35],
            "short_terminal_name": "",
            "user": "",
            "transaction_code": "",
            "program": "",
            "long_terminal_name": "",
            "last_address_routed_no_of_variables": "",
            "first_variable_value": "",
            "second_variable_value": "",
            "third_variable_value": "",
            "audit_log_msg_text": "",
            "long_version_of_event": data[35:], 
            "audit_class": "", 
            "message_severity": "", 
            "criticality": "M", 
            "other_variable_values": "123",  
        }

        
        if message_template:
            first_variable_value = "100"
            second_variable_value = "200"
            third_variable_value = "300"
            
            formatted_message = format_message(
                message_template["message_text"], 
                first_variable_value, 
                second_variable_value, 
                third_variable_value
            )
            
            parsed_data.update({
                "audit_log_msg_text": formatted_message,
                "audit_class": message_template["audit_class"],
                "message_severity": message_template["message_severity"],
                "criticality": "H" if message_template["message_severity"] == "High" else "M",
                "first_variable_value": first_variable_value,
                "second_variable_value": second_variable_value,
                "third_variable_value": third_variable_value
            })
        index = 35
        
        parsed_data["short_terminal_name"], index = extract_variable_length_field(data, index)
        parsed_data["user"], index = extract_variable_length_field(data, index)
        parsed_data["transaction_code"], index = extract_variable_length_field(data, index)
        parsed_data["program"], index = extract_variable_length_field(data, index)
        parsed_data["long_terminal_name"], index = extract_variable_length_field(data, index)
        parsed_data["last_address_routed_no_of_variables"], index = extract_variable_length_field(data, index)
        
        variables= data[start_idx+4]
    
        
        variables = parsed_data["last_address_routed_no_of_variables"].split()
        parsed_data["first_variable_value"] = variables[0] if len(variables) > 0 else ""
        parsed_data["second_variable_value"] = variables[1] if len(variables) > 1 else ""
        parsed_data["third_variable_value"] = variables[2] if len(variables) > 2 else ""
        
        parsed_data["long_version_of_event"] = data[index:]

        parsed_logs.append(parsed_data)

    return parsed_logs

def save_parsed_logs(db: Session, parsed_logs: list):
    for entry in parsed_logs:
        print(entry)
        new_log = LogEntry(**entry)
        db.add(new_log)
    db.commit()


def parse_and_store_logs(file_path: str, db: Session):
    parsed_segments = process_aud_file(file_path)
    parsed_logs = parse_log_data(parsed_segments)
    save_parsed_logs(db, parsed_logs)
    
    
    
    
    
    
    
    
    
    
    
    


