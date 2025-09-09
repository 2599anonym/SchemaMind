import json
from time import sleep
import dashscope
from http import HTTPStatus


dashscope.api_key = ""



class Detector:
    def __init__(self, bg=""):
        self.bg = bg

    def get_answer(self, prompt, conversation_history=None):
        if conversation_history:
            messages = conversation_history + [{'role': 'user', 'content': prompt}]
        else:
            messages = [{'role': 'user', 'content': prompt}]

        wrong = 0
        while True:
            try:
                response = dashscope.Generation.call(
                    model='qwen-turbo-2025-07-15',
                    messages=messages,
                    result_format='message',
                    max_tokens=2048,
                )
                if response.status_code == HTTPStatus.OK:
                    return response.output.choices[0]['message']
                else:
                    print('Request failed, status_code: %s, code: %s, message: %s' %
                          (response.status_code, response.code, response.message))
                    wrong += 1
                    if wrong < 10:
                        sleep(15)
                        continue
                    return None  
            except Exception as e:
                print("Request Error", e)
                wrong += 1
                if wrong < 10:
                    sleep(15)
                    continue
                return None 

    def detect(self, prompt, conversation_history=None):
        num = 0
        while True:
            # <<< 修改点 #3：将conversation_history传递给get_answer >>>
            response_message = self.get_answer(prompt, conversation_history)

            if response_message:
                text = response_message.get('content', '')  # 安全地获取文本内容
                Js = self.is_json(text)
                if Js:
                    # <<< 修改点 #4：同时返回解析结果和原始消息对象 >>>
                    return Js, response_message
                else:
                    num += 1
                    if num > 10:
                        return None, None  # 返回两个None表示最终失败
                    else:
                        sleep(1)
                        continue
            else:  # get_answer返回None，表示API请求失败
                num += 1
                if num > 10:
                    return None, None
                else:
                    continue

    def is_json(self, text):
        cleaned_text = text.strip()
        if cleaned_text.startswith("```json"):
            cleaned_text = cleaned_text[7:-3].strip()
        if not cleaned_text:
            print("Json Format Error: Received an empty string after cleaning.")
            return False
        # print("Cleaned text to parse:", cleaned_text) # 调试时可以取消注释
        try:
            Js = json.loads(cleaned_text)
        except ValueError:
            # print("Json Format Error:", e) # 调试时可以取消注释
            return False
        return Js