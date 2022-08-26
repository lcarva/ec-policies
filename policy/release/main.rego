package release.main

import data.lib

all_denies := lib.current_and_future_denies("release")

all_warns := lib.current_and_future_warns("release")

deny_stuff := lib.current_rules(all_denies)

warn_stuff := lib.future_rules(all_denies) | lib.current_rules(all_warns)
