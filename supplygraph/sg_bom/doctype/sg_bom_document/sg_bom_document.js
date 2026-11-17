// Copyright (c) 2026, Lifegence and contributors
// License: Apache-2.0. See LICENSE

const EXPORT_FORMATS = ["CycloneDX", "SPDX"];

frappe.ui.form.on("SG BOM Document", {
	refresh(frm) {
		// A cancelled SBOM is not handed to anyone
		if (frm.is_new() || frm.doc.docstatus === 2) {
			return;
		}
		for (const format of EXPORT_FORMATS) {
			frm.add_custom_button(format, () => export_bom(frm, format, false), __("Export SBOM"));
		}
	},

	before_workflow_action(frm) {
		if (frm.selected_workflow_action !== "Accept" || frm.doc.subject_release) {
			return;
		}
		// A document for no release is allowed, such as the SBOM of a nested component.
		// The workflow froze the page before this event, and the freeze would cover the dialog.
		frappe.dom.unfreeze();
		// On No the promise stays pending, which stops the action without an unhandled rejection.
		return new Promise((resolve) => {
			frappe.confirm(
				__(
					"Subject Release is empty, so this SBOM will not appear in Vulnerability Impact. Accept it anyway?"
				),
				() => {
					frappe.dom.freeze();
					resolve();
				}
			);
		});
	},
});

function export_bom(frm, format, force) {
	if (frm.is_dirty()) {
		frappe.msgprint(__("Save the document before exporting it."));
		return;
	}
	frappe.call({
		method: "supplygraph.sg_bom.export.export_bom",
		type: "POST",
		args: { bom_document: frm.doc.name, format: format, force: force ? 1 : 0 },
		freeze: true,
		freeze_message: __("Exporting {0}...", [format]),
		error_handlers: {
			// The document has validation errors: show them and let the user export anyway
			SbomHasErrorsError: (r) => {
				frm.reload_doc();
				frappe.warn(
					__("SBOM Has Errors"),
					server_message(r) + "<br><br>" + __("Export it anyway?"),
					() => export_bom(frm, format, true),
					__("Export Anyway")
				);
			},
		},
		callback(r) {
			const result = r.message;
			if (!result) {
				return;
			}
			download(result.filename, result.content);
			if (result.warnings && result.warnings.length) {
				frappe.msgprint({
					title: __("Exported with Warnings"),
					indicator: "orange",
					message: result.warnings
						.map((warning) => frappe.utils.escape_html(warning))
						.join("<br>"),
				});
			}
			// The validation before the export recorded its result on the document
			if (!force) {
				frm.reload_doc();
			}
		},
	});
}

function server_message(r) {
	// _server_messages is a JSON list of JSON objects; the server already escaped the text
	const messages = JSON.parse(r._server_messages || "[]").map((m) => JSON.parse(m).message);
	return messages.join("<br>");
}

function download(filename, content) {
	const link = document.createElement("a");
	link.href = URL.createObjectURL(new Blob([content], { type: "application/json" }));
	link.download = filename;
	document.body.appendChild(link);
	link.click();
	document.body.removeChild(link);
	// Revoking at once can cancel the download in some browsers
	setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}
