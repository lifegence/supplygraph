// Copyright (c) 2026, Lifegence and contributors
// License: Apache-2.0. See LICENSE

frappe.listview_settings["SG Component"] = {
	add_fields: ["review_status"],
	get_indicator(doc) {
		if (doc.review_status === "Needs Review") {
			return [__("Needs Review"), "orange", "review_status,=,Needs Review"];
		}
	},
	onload(listview) {
		if (!frappe.model.can_write("SG Component")) {
			return;
		}
		listview.page.add_inner_button(__("Find Duplicates"), () => {
			frappe.call({
				method: "supplygraph.sg_catalog.component_merge.mark_duplicates",
				callback() {
					listview.filter_area.add([
						["SG Component", "review_status", "=", "Needs Review"],
					]);
				},
			});
		});
		if (!frappe.model.can_delete("SG Component")) {
			return;
		}
		listview.page.add_action_item(__("Merge Components"), () => {
			const items = listview.get_checked_items();
			const selected = items.map((item) => item.name);
			if (selected.length < 2) {
				frappe.msgprint(__("Select at least two components"));
				return;
			}
			frappe.prompt(
				{
					fieldname: "target",
					label: __("Component to keep"),
					fieldtype: "Select",
					options: items.map((item) => ({
						label: `${item.component_name} (${item.name})`,
						value: item.name,
					})),
					reqd: 1,
				},
				({ target }) => {
					frappe.call({
						method: "supplygraph.sg_catalog.component_merge.merge_components",
						args: { target, sources: selected },
						callback() {
							frappe.show_alert({ message: __("Merged"), indicator: "green" });
							listview.refresh();
						},
					});
				},
				__("Merge Components"),
				__("Merge")
			);
		});
	},
};
