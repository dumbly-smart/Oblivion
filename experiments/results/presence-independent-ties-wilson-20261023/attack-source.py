"""Primitive set intersection over declared public participation and beacon epochs."""
import random

MODES = ('intermittent_control', 'fixed_rate_online', 'always_participating')
FIELDS = {'mode', 'epoch', 'incoming', 'missing_slots', 'outgoing', 'incoming_bytes',
          'outgoing_bytes', 'emit_ns', 'late_by_ns'}


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('integer out of bounds')
    return value


def _slots(values):
    if not isinstance(values, list) or len(values) > 8:
        raise ValueError('slot list')
    for value in values:
        _integer(value, 0, 7)
    if values != sorted(set(values)):
        raise ValueError('slots must be sorted and unique')
    return set(values)


def intersect(trace, beacon, *, knowledge_events=None, observer='incoming', seed=0):
    """No target truth is accepted; uniform candidate scores are uncalibrated."""
    if not isinstance(trace, list) or not 1 <= len(trace) <= 4096:
        raise ValueError('trace bound')
    if not isinstance(beacon, list) or len(beacon) != len(trace):
        raise ValueError('beacon length')
    _integer(seed, 0, 2**64 - 1)
    if knowledge_events is not None:
        _integer(knowledge_events, 1, 4096)
    if observer not in ('incoming', 'missing_slots', 'downstream'):
        raise ValueError('observer')
    if not isinstance(trace[0], dict):
        raise ValueError('observer schema')
    candidates = set(range(8)); used = 0; mode = trace[0].get('mode')
    if mode not in MODES:
        raise ValueError('mode')
    for epoch, (row, event) in enumerate(zip(trace, beacon)):
        if not isinstance(row, dict) or set(row) != FIELDS or row['mode'] != mode:
            raise ValueError('observer schema')
        if not isinstance(event, dict) or set(event) != {'epoch', 'event'}:
            raise ValueError('beacon schema')
        _integer(row['epoch'], 0, 4095); _integer(event['epoch'], 0, 4095)
        if row['epoch'] != epoch or event['epoch'] != epoch or type(event['event']) is not bool:
            raise ValueError('epoch or event')
        incoming = _slots(row['incoming']); missing = _slots(row['missing_slots'])
        outgoing = _slots(row['outgoing'])
        if incoming & missing or incoming | missing != set(range(8)) or outgoing != set(range(8)):
            raise ValueError('participation partition')
        for field in ('incoming_bytes', 'outgoing_bytes', 'emit_ns', 'late_by_ns'):
            _integer(row[field], 0, 10**15)
        if row['incoming_bytes'] != len(incoming)*164 or row['outgoing_bytes'] != 8*164:
            raise ValueError('byte accounting')
        if row['emit_ns'] != (epoch+1)*10_000_000 or row['late_by_ns'] != 0:
            raise ValueError('virtual schedule')
        if event['event'] and (knowledge_events is None or used < knowledge_events):
            visible = incoming if observer == 'incoming' else set(range(8))-missing
            if observer == 'downstream':
                visible = outgoing
            candidates &= visible; used += 1
    order = list(range(8)); random.Random(seed).shuffle(order)
    ranking = [slot for slot in order if slot in candidates]
    return {'candidates': sorted(candidates), 'ranking': ranking, 'events_used': used,
            'scores': {str(slot): 1/len(candidates) for slot in candidates},
            'score_semantics': 'UNCALIBRATED uniform compatibility, not posterior probability'}
