from fastapi import Request
from urllib.parse import urlencode
import httpx
import secrets
import base64
from fastapi import HTTPException
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
import asyncio,json,requests
import hashlib
from fastapi.responses import HTMLResponse
from integrations.integration_item import IntegrationItem


CLIENT_ID = 'CLIENT_ID'
CLIENT_SECRET = 'CLIENT_SECRET'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback' 
HUBSPOT_TOKEN_URL = "https://api.hubapi.com/oauth/v1/token"
HUBSPOT_SCOPES = "crm.objects.contacts.read crm.objects.contacts.write"

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode('utf-8'))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode('utf-8').replace('=', '')
    hubspot_auth_url = f"https://app.hubspot.com/oauth/authorize"
    auth_url = (
    f"{hubspot_auth_url}?"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri={REDIRECT_URI}&"
    f"state={encoded_state}&"
    f"code_challenge={code_challenge}&"
    f"code_challenge_method=S256&"
    f"scope={HUBSPOT_SCOPES}"
    )
    
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=100),
        add_key_value_redis(f'hubspot_verifier:{org_id}:{user_id}', code_verifier, expire=100),
    )
    return auth_url



async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f'hubspot_state:{org_id}:{user_id}'),
        get_value_redis(f'hubspot_verifier:{org_id}:{user_id}'),
    )

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')


    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": code
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(HUBSPOT_TOKEN_URL, data=data)
            response.raise_for_status()
            # token_response = response.json()
            await delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
            await delete_key_redis(f'hubspot_verifier:{org_id}:{user_id}'),
        await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=100)


    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=str(e))
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    # Fetch credentials from your database/redis
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    print(credentials)
    return json.loads(credentials)


async def fetch_items(access_token, url, list_of_responses):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        list_of_responses.extend(data.get('results', []))

def create_integration_item_metadata_object(response, item_type, parent_id=None, parent_name=None):
    # Adjust this method based on the response structure from HubSpot
    metadata = {
        'id': response.get('id'),
        'type': item_type,
        'name': response.get('properties', {}).get('firstname', 'Unknown'),
    }
    if parent_id:
        metadata['parent_id'] = parent_id
    if parent_name:
        metadata['parent_name'] = parent_name
    return metadata


async def get_items_hubspot(credentials):
    credentials = json.loads(credentials)
    url = 'https://api.hubapi.com/crm/v3/objects/contacts'
    list_of_integration_item_metadata = []
    list_of_responses = []

    # Fetch items from HubSpot
    await fetch_items(credentials.get('access_token'), url, list_of_responses)

    # Process the fetched contacts
    for response in list_of_responses:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(response, 'Contact')
        )
        
        # If you want to fetch associated records (e.g., deals) for each contact
        associated_records_response = requests.get(
            f'https://api.hubapi.com/crm/v3/objects/contacts/{response.get("id")}/associations/companies',
            headers={'Authorization': f'Bearer {credentials.get("access_token")}'},
        )
        if associated_records_response.status_code == 200:
            associated_records = associated_records_response.json()
            for record in associated_records['results']:
                list_of_integration_item_metadata.append(
                    create_integration_item_metadata_object(
                        record,
                        'Deal',
                        response.get('id', None),
                        response.get('properties', {}).get('firstname', None),
                    )
                )

    print(f'list_of_integration_item_metadata: {list_of_integration_item_metadata}')
    return list_of_integration_item_metadata