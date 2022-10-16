import asyncio
import aiohttp
import json

# We need a new session so as to set the header.
# Any redirect will strip the Authorizatoin header.
async def access_protected_area(token):

    print(f"Accessing protected content with token: {token}...", end="")
    auth_header_content = f"Bearer {token}"

    authorization_header = {
        "Authorization": auth_header_content
    }

    async with aiohttp.ClientSession(headers=authorization_header) as session:
        async with session.get('http://localhost:8000/users/me') as response:
            js = await response.json()
            
            if response.status == 200:
                print("Success")
                return True
            else:
                print("Failed to access")
                return False


async def do_authentication(session):

    user_pass_form = aiohttp.FormData()
    user_pass_form.add_field("grant_type", "password")
    user_pass_form.add_field("username", "johndoe")
    user_pass_form.add_field("password", "secret")

    async with session.post('http://localhost:8000/token', data=user_pass_form) as response:
        print("Authenticating with username and password")
        return await response.json()


async def start():

    token = None
    async with aiohttp.ClientSession() as session:
        async with session.get('http://localhost:8000/users/me') as response:

            print("Status:", response.status)
            print("Content-type:", response.headers['content-type'])

            scheme = response.headers['WWW-Authenticate']

            # Only bearer is supported...
            if scheme == "Bearer":
                print("Bearer token returned: now to try authenticating...")

                access = await do_authentication(session)

                if 'access_token' in access:
                    token = access['access_token']
                    success = await access_protected_area(token)

                    if success:
                        print("Flow completed fully")
                    else:
                        print("There was problem...")
                else:
                    print(f"From server: {access['detail']}")
                    return


"""
The initial call to the /usrs/me end point will result in a 401 PLUS a header of the 
form b'www-authenticate', b'Bearer', which states that scheme in use here is via
bearer token; that can be anything but is usually a JWT eg DAI.

"""
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(start())