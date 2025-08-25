# Author: Matthias Maderer
# E-Mail: matthias.maderer@web.de
# URL: https://github.com/edvler/check_mk_proxmox-qemu-backup
# License: GPLv2

from cmk.rulesets.v1 import (
    Title,
)
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    InputHint,
    LevelDirection,
    migrate_to_upper_float_levels,
    SimpleLevels,
    TimeMagnitude,
    TimeSpan,
    Integer
    )
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    HostAndItemCondition,
    Topic,
)

def _parameter_proxmox_bs_clients():
    return Dictionary(
        migrate=lambda model: { #force defaults for with model.get(...,DEFAULT)
            'bkp_age': migrate_to_upper_float_levels(model.get('backup_age',('fixed',(1.5 * 86400.0, 2 * 86400.0)))),
            'snapshot_min_ok': model.get('snapshot_min_ok',1),
        },        
        elements={
            'bkp_age': DictElement(
                required=True,
                parameter_form=SimpleLevels(
                    title = Title('Age of last Snapshot with state verified OK before changing to warn or critical'),
                    #migrate = lambda model: migrate_to_upper_float_levels(model),
                    level_direction = LevelDirection.UPPER,
                    form_spec_template = TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR, TimeMagnitude.MINUTE],
                    ),
                    prefill_fixed_levels = InputHint(
                        value=(1.5 * 86400.0, 2 * 86400.0),
                    )
                )
            ),
            'snapshot_min_ok': DictElement(
                required=True,
                parameter_form=Integer(
                    #migrate = lambda model: _migrate_snapshot_min_ok(model),
                    title = Title('Minimum Snapshots with state verified OK'),
                    #help=_("Change to warn, if not enough snapshots stored on the PBS Server")
                    prefill=DefaultValue(1)
                )
            ),
        }
    )

rule_spec_urbackup = CheckParameters(
    name="proxmox_bs_clients",
    topic=Topic.STORAGE,
    parameter_form=_parameter_proxmox_bs_clients,
    title=Title("Proxmox Backup Server (PBS) Clients"),
    condition=HostAndItemCondition(item_title=Title("'PBS Client ID")),
)