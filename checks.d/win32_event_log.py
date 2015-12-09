'''
Monitor the Windows Event Log
'''
# stdlib
import calendar
from datetime import datetime, timedelta

# 3rd party
import wmi

# project
from checks.wmi import WinWMICheck

SOURCE_TYPE_NAME = 'event viewer'
EVENT_TYPE = 'win32_log_event'

class Win32EventLogWMI(WinWMICheck):
    EVENT_PROPERTIES = [
        "Message",
        "SourceName",
        "TimeGenerated",
        "Type",
        "User",
        "InsertionStrings",
        "EventCode"
    ]
    NAMESPACE = "root\\CIMV2"
    CLASS = "Win32_NTLogEvent"

    def __init__(self, name, init_config, agentConfig, instances=None):
        WinWMICheck.__init__(self, name, init_config, agentConfig,
                            instances=instances)
        self.last_ts = {}
        self.filters = []

    def check(self, instance):
        # Connect to the WMI provider
        host = instance.get('host', "localhost")
        username = instance.get('username', "")
        password = instance.get('password', "")
        instance_tags = instance.get('tags', [])
        notify = instance.get('notify', [])

        ltype = instance.get('type')
        user = instance.get('user')
        source_name = instance.get('source_name')
        log_file = instance.get('log_file')
        event_id = instance.get('event_id')

        instance_key = self._get_instance_key(host, self.NAMESPACE, self.CLASS)

        # Store the last timestamp by instance
        if instance_key not in self.last_ts:
            self.last_ts[instance_key] = datetime.utcnow()
            return

        last_ts = self.last_ts[instance_key]
        self.filters += [{'TimeGenerated': ('>=', self._dt_to_wmi(last_ts))}]
        if ltype:
            self.filters += [{'Type': ('=', ltype)}]
        if user:
            self.filters += [{'User': ('=', user)}]
        if event_id:
            self.filters += [{'EventCode': ('=', event_id)}]
        if source_name:
            self.filters += [{'SourceName': ('=', source_name)}]
        if log_file:
            self.filters += [{'LogFile': ('=', log_file)}]

        wmi_sampler = self._get_wmi_sampler(
            instance_key,
            self.CLASS, self.EVENT_PROPERTIES,
            filters=self.filters,
            host=host, namespace=self.NAMESPACE,
            username=username, password=password,
            inclusive=False
        )

        wmi_sampler.sample()

        events = self._extract_events(wmi_sampler)
        for ev in events:
            log_ev = LogEvent(ev, self.agentConfig.get('api_key', ''),
                              self.hostname, instance_tags, notify,
                              self.init_config.get('tag_event_id', False))

            # Since WQL only compares on the date and NOT the time, we have to
            # do a secondary check to make sure events are after the last
            # timestamp
            if log_ev.is_after(last_ts):
                self.event(log_ev.to_event_dict())
            else:
                self.log.debug('Skipping event after %s. ts=%s' % (last_ts, log_ev.timestamp))

        # Update the last time checked
        self.last_ts[instance_key] = datetime.utcnow()


    def _extract_events(self, wmi_sampler):
        events = []
        for wmi_obj in wmi_sampler:
            events.append(wmi_obj)

        return events

    def _dt_to_wmi(self, dt):
        ''' A wrapper around wmi.from_time to get a WMI-formatted time from a
            time struct.
        '''
        return wmi.from_time(year=dt.year, month=dt.month, day=dt.day,
                             hours=dt.hour, minutes=dt.minute,
                             seconds=dt.second, microseconds=0, timezone=0)


class LogEvent(object):
    def __init__(self, ev, api_key, hostname, tags, notify_list, tag_event_id):
        self.event = ev
        self.api_key = api_key
        self.hostname = hostname
        self.tags = self._tags(tags, ev.EventCode) if tag_event_id else tags
        self.notify_list = notify_list
        self.timestamp = self._wmi_to_ts(self.event['TimeGenerated'])

    def to_event_dict(self):
        return {
            'timestamp': self.timestamp,
            'event_type': EVENT_TYPE,
            'api_key': self.api_key,
            'msg_title': self._msg_title(self.event),
            'msg_text': self._msg_text(self.event).strip(),
            'aggregation_key': self._aggregation_key(self.event),
            'alert_type': self._alert_type(self.event),
            'source_type_name': SOURCE_TYPE_NAME,
            'host': self.hostname,
            'tags': self.tags
        }

    def is_after(self, ts):
        ''' Compare this event's timestamp to a give timestamp. '''
        if self.timestamp >= int(calendar.timegm(ts.timetuple())):
            return True
        return False

    def _wmi_to_ts(self, wmi_ts):
        ''' Convert a wmi formatted timestamp into an epoch using wmi.to_time().
        '''
        year, month, day, hour, minute, second, microsecond, tz = wmi.to_time(wmi_ts)
        tz_delta = timedelta(minutes=int(tz))
        if '+' in wmi_ts:
            tz_delta = - tz_delta

        dt = datetime(year=year, month=month, day=day, hour=hour, minute=minute,
                      second=second, microsecond=microsecond) + tz_delta
        return int(calendar.timegm(dt.timetuple()))

    def _tags(self, tags, event_code):
        ''' Inject additional tags into the list already supplied to LogEvent.
        '''
        tags_list = []
        if tags is not None:
            tags_list += list(tags)
        tags_list.append("event_id:{event_id}".format(event_id=event_code))
        return tags_list

    def _msg_title(self, event):
        return '%s/%s' % (event['Logfile'], event['SourceName'])

    def _msg_text(self, event):
        msg_text = ""
        if 'Message' in event:
            msg_text = "%s\n" % event['Message']
        elif 'InsertionStrings' in event:
            msg_text = "\n".join([i_str for i_str in event['InsertionStrings']
                                  if i_str.strip()])

        if self.notify_list:
            msg_text += "\n%s" % ' '.join([" @" + n for n in self.notify_list])

        return msg_text

    def _alert_type(self, event):
        event_type = event['Type']
        # Convert to a Datadog alert type
        if event_type == 'Warning':
            return 'warning'
        elif event_type == 'Error':
            return 'error'
        return 'info'

    def _aggregation_key(self, event):
        return event['SourceName']
