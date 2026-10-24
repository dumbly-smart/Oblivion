"""Controlled local chosen-update association; no target labels are accepted.

The adversary links an observed chosen posting to prior opaque search events.
It does not infer plaintext words and does not interact with external services.
"""
import random

def recover_links(rows,mode,seed=0):
    rows=[r for r in rows if r['mode']==mode]
    old=[r for r in rows if r['phase']=='past_search'];updates=[r for r in rows if r['phase']=='injected_update'];fresh=[r for r in rows if r['phase']=='fresh_search']
    if not old or not updates:raise ValueError('missing past observations or chosen updates')
    tags={tuple(r['request']['tag']):r['slot'] for r in old}
    past_addresses={tuple(entry['address']):r['slot'] for r in old for entry in r['response']['entries']}
    next_addresses={tuple(entry['address']):tags[tuple(r['request']['tag'])] for r in fresh for entry in r['response']['entries']}
    if len(tags)!=len(old):raise ValueError('ambiguous past search fixture')
    rng=random.Random(seed);guesses=list(tags.values());rng.shuffle(guesses)
    before=[];after=[];matches=0
    for index,update in enumerate(updates):
        request=update['request'];address=tuple(request['address'])
        match=tags.get(tuple(request.get('stable_tag',[])),past_addresses.get(address))
        matches+=match is not None
        before.append(match if match is not None else guesses[index%len(guesses)])
        if address not in next_addresses:raise ValueError('fresh search failed to authorize known posting')
        after.append(next_addresses[address])
    return {'before_predictions':before,'after_predictions':after,'before_matches':matches,'after_matches':len(after),
            'knowledge':'chosen posting update events and all prior/fresh server-visible search requests/responses, no plaintext target word labels',
            'limits':'before-stage capability checks only previously authorized address set and stable update tags; not a general forward-privacy proof'}
