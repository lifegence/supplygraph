# Copyright (c) 2026, Lifegence and contributors
# License: Apache-2.0. See LICENSE

from supplygraph.sg_vulnerability.vex import refresh_vex_handled


def execute():
	# Matches of releases assessed before the field existed
	refresh_vex_handled()
