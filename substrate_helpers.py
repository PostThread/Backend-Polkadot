import re
import json
import substrateinterface
from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException
import ipfshttpclient
from os import listdir
from os.path import isfile, join

substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944",
    ss58_format=42,
    type_registry_preset='kusama'
)

delegate = Keypair.create_from_uri('//Ferdie')
client = ipfshttpclient.connect()

schemas = json.load(open("schemas.json"))

def reload_schemas():
    global schemas
    schemas = json.load(open("schemas.json"))

def get_signature(payload, signer):
    # encode payload using SCALE
    # I found scale_info from "substrate.metadata_decoder"
    payload_encoded = substrate.encode_scale(type_string='u64', value=payload['authorized_msa_id']) + \
                            substrate.encode_scale(type_string='vec<u16>', value=payload['schema_ids']) + \
                            substrate.encode_scale(type_string='u32', value=payload['expiration'])

    # Payload must be wrapped in theses Bytes objects
    payload_encoded = "<Bytes>".encode() + payload_encoded.data + "</Bytes>".encode()

    # The provider address signs the payload, so in this case alice
    return signer.sign(payload_encoded)

def get_attributes_from_event(receipt):    
    for event in receipt.triggered_events:
        event = event.decode()
        if event['event']['event_id'].strip() in ['MsaCreated', 'SchemaCreated']:
            return event['event']['attributes']
    
    raise Exception(receipt.triggered_events)

def make_call(call_module, call_function, call_params, keypair, wait_for_inclusion=True):    
    call = substrate.compose_call(
        call_module=call_module,  
        call_function=call_function,
        call_params=call_params
    )

    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)

    try:
        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=wait_for_inclusion)
        if wait_for_inclusion and receipt.error_message is not None:
            raise Exception(receipt.error_message)
        
        return receipt

    except SubstrateRequestException as e:
        raise Exception("Failed to send: {}".format(e))
    
def getSchemaId(schema):
    schema_count = substrate.query(
        module='Schemas',
        storage_function='CurrentSchemaIdentifierMaximum',
        params=[]
    ).value

    for i in range(1, schema_count+1):
        schemaTemp = substrate.query(
            module='Schemas',
            storage_function='Schemas',
            params=[i]
        )
        
        if json.loads(schemaTemp.value['model']) == schema:
            schema_id = i
            return schema_id

def add_schema(schema, is_ipfs=False, check=True, wait_for_inclusion=True):
    schema_id = None
    if check:
        schema_id = getSchemaId(schema)

    schema = '0x'+json.dumps(schema).encode().hex()
    if schema_id is None:
        payload = {"model": schema, "model_type": "AvroBinary", "payload_location": "IPFS" if is_ipfs else "OnChain"}
        receipt = make_call("Schemas", "create_schema", payload, delegate, wait_for_inclusion=wait_for_inclusion)
        schema_id = get_attributes_from_event(receipt)[1]
        
        return schema_id, receipt
            
    return schema_id, None

def get_msa_id(wallet):
    msa_id = substrate.query(
        module='Msa',
        storage_function='PublicKeyToMsaId',
        params=[wallet.ss58_address]
    ).value
    
    return msa_id

def create_msa_id(wallet):
    msa_id = get_msa_id(wallet)
    if msa_id is not None:
        return msa_id

    receipt = make_call("Msa", "create", {}, wallet)
    msa_id = get_attributes_from_event(receipt)['msa_id']
        
    return msa_id

def get_call_params(provider_msa_id, delegator_wallet):
    expiration = substrate.get_block()['header']['number'] + 100
    payload_raw = { "authorized_msa_id": provider_msa_id, "schema_ids": list(schemas.values()) , "expiration": expiration}
    signature = get_signature(payload_raw, delegator_wallet)

    call_params = {
        "delegator_key": delegator_wallet.ss58_address,
        "proof": {"Sr25519": "0x" + signature.hex()},
        "add_provider_payload": payload_raw
    }
    return call_params

def add_delegate(provider_msa_id, user_wallet):
    call_params = get_call_params(provider_msa_id, user_wallet)

    receipt = make_call("Msa", "add_provider_to_msa", call_params, user_wallet, wait_for_inclusion=False)
    return receipt

def create_msa_with_delegator(provider_wallet, delegator_wallet, wait_for_inclusion=True):
    msa_id = get_msa_id(delegator_wallet)
    if msa_id is not None:
        return msa_id
            
    provider_msa_id = create_msa_id(provider_wallet)

    call_params = get_call_params(provider_msa_id, delegator_wallet)

    # provider signs this
    receipt = make_call("Msa", "create_sponsored_account_with_delegation", call_params, provider_wallet, wait_for_inclusion=wait_for_inclusion)
    msa_id = get_attributes_from_event(receipt)['msa_id']
    return msa_id

def mint_ipfs_data(data, user_msa_id, schema_id, path, wait_for_inclusion=True):
    # write to temp file first to get hash from ipfs
    json.dump(data, open(f"temp.json", "w"))
    data_hash = client.add('temp.json', only_hash=True)["Hash"]
    
    # use hash to check if we already added this post to the blockchain
    # if so then skip
    data_files = [f for f in listdir(path) if isfile(join(path, f))]
    file = f"{path}{data_hash}.json"
    if file in data_files:
        return data_hash, None

    json.dump(data, open(file, "w"))
    res_post = client.add(file)
    hash = res_post["Hash"]
    size = res_post['Size']

    call_params = {
        "schema_id": schema_id,
        "cid": hash,
        "payload_length": size,
    }
    receipt_post = make_call("Messages", "add_ipfs_message", call_params, delegate, wait_for_inclusion=wait_for_inclusion)

    return hash, receipt_post

def mint_onchain_data(data, user_msa_id, schema_id, wait_for_inclusion=True):
    call_params = {
        "on_behalf_of": user_msa_id,
        "schema_id": schema_id,
        "payload": data,
    }
    receipt_post = make_call("Messages", "add_onchain_message", call_params, delegate, wait_for_inclusion=wait_for_inclusion)

    return receipt_post

def mint_votes(user_msa_id, num_votes, parent_hash, post_data_hash, parent_type, wait_for_inclusion=False):
    message = '{' + f'"post_hash": "{post_data_hash}", "parent_hash": "{parent_hash}","parent_type": "{parent_type}","num_votes": {num_votes}' + '}'
    receipt = mint_onchain_data(message, user_msa_id, schemas['vote'], wait_for_inclusion=wait_for_inclusion)

    return receipt

def mint_user(user_msa_id, username, profile_pic, user_wallet, wait_for_inclusion=False): 
    user_data = '{' + f'"msa_id": {user_msa_id},"username": "{username}","profile_pic": "{profile_pic}","wallet_ss58_address": "{user_wallet.ss58_address}"' + '}'
    receipt_user = mint_onchain_data(user_data, user_msa_id, schemas['user'], wait_for_inclusion=wait_for_inclusion)
    return receipt_user

def follow_user(protagonist_msa_id, antagonist_msa_id, is_follow=True, wait_for_inclusion=False):
    follow = "follow" if is_follow else "unfollow"
    message = '{' + f'"protagonist_msa_id": {protagonist_msa_id},"antagonist_msa_id": "{antagonist_msa_id}","event": "{follow}"' + '}'
    receipt_follow = mint_onchain_data(message, protagonist_msa_id, schemas['follow'], wait_for_inclusion=wait_for_inclusion)
    return receipt_follow