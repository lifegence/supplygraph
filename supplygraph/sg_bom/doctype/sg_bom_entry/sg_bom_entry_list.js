// Copyright (c) 2026, Lifegence and contributors
// License: Apache-2.0. See LICENSE

frappe.listview_settings["SG BOM Entry"] = {
	add_fields: ["scope"],
	onload(listview) {
		if (!frappe.model.can_write("SG BOM Entry")) {
			return;
		}
		// For SBOMs that do not mark development-only components themselves (scope "excluded")
		const mark = (development_only, label, done) => {
			listview.page.add_action_item(label, () => {
				frappe.call({
					method: "supplygraph.sg_bom.flatten.set_development_only",
					args: { names: listview.get_checked_items(true), development_only },
					callback(r) {
						frappe.show_alert({ message: done(r.message), indicator: "green" });
						listview.clear_checked_items();
						listview.refresh();
					},
				});
			});
		};
		mark(1, __("Mark as Development Only"), (count) =>
			__("{0} entries marked as development only", [count])
		);
		mark(0, __("Unmark Development Only"), (count) =>
			__("{0} entries no longer marked as development only", [count])
		);
	},
};
