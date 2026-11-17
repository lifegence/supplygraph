// Copyright (c) 2026, Lifegence and contributors
// License: Apache-2.0. See LICENSE

frappe.listview_settings["SG BOM Document"] = {
	onload(listview) {
		if (!frappe.model.can_create("SG BOM Document")) {
			return;
		}
		listview.page.add_inner_button(__("Import SBOM"), () => {
			new frappe.ui.FileUploader({
				folder: "Home/Attachments",
				is_private: 1,
				restrictions: { allowed_file_types: [".json", ".spdx"] },
				on_success(file) {
					frappe.call({
						method: "supplygraph.sg_bom.importer.enqueue_import",
						args: { file_url: file.file_url },
						callback() {
							frappe.show_alert({
								message: __("SBOM import started"),
								indicator: "blue",
							});
						},
					});
				},
			});
		});
		frappe.realtime.on("sg_bom_import_done", (data) => {
			if (data.error) {
				frappe.msgprint({
					title: __("SBOM import failed"),
					message: data.error,
					indicator: "red",
				});
				return;
			}
			if (data.validation_error) {
				frappe.msgprint({
					title: __("SBOM imported, but validation failed: {0}", [data.bom_document]),
					message: data.validation_error,
					indicator: "orange",
				});
			} else if (data.import_status === "Rejected") {
				frappe.show_alert({
					message: __("SBOM imported, but rejected by validation: {0}", [
						data.bom_document,
					]),
					indicator: "orange",
				});
			} else {
				frappe.show_alert({
					message: __("SBOM imported: {0}", [data.bom_document]),
					indicator: "green",
				});
			}
			listview.refresh();
		});
	},
};
