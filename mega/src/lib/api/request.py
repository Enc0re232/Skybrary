import aiohttp
import asyncio
import logging
from src.exeptions import RequestError
from typing import List, Union
import json

logger: logging.Logger = logging.getLogger(__name__)

def api_request(params: dict, data:Union[list|dict], schema:str, domain:str, timeout:int):
        # ensure input data is a list
        if not isinstance(data, list):
            data = [data]


        url = f'{schema}://g.api.{domain}/cs'
        response_text = asyncio.run(send_request("POST", url, params, data, timeout))
        print(response_text)
        
        json_resp = json.loads(response_text)
        try:
            if isinstance(json_resp, list):
                int_resp = json_resp[0] if isinstance(json_resp[0],
                                                      int) else None
            elif isinstance(json_resp, int):
                int_resp = json_resp
        except IndexError:
            int_resp = None
        if int_resp is not None:
            if int_resp == 0:
                return int_resp
            if int_resp == -3:
                msg = 'Request failed, retrying'
                logger.info(msg)
                raise RuntimeError(msg)
            raise RequestError(int_resp)
        return json_resp[0]
    
async def send_request(method:str, url: str, params:dict, data:List[dict], timeout:int):
    match method:
        case 'GET':
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, data=json.dumps(data), timeout=timeout) as response:
                    if response.status != 200:
                        return await response.text()
                    else:
                        raise Exception('Request failed, retrying')
                        retry()
        case 'POST':
            async with aiohttp.ClientSession() as session:
                async with session.post(url, params=params, data=json.dumps(data), timeout=timeout) as response:
                    if response.status != 200 or response.status != 201:
                        return await response.text()
                    else:
                        raise Exception('Request failed, retrying')
        
# async def get_request_data(method:str, url: str, params:dict, data:List[dict], timeout:int):
#     return await send_post_request(method, url, params, data, timeout)