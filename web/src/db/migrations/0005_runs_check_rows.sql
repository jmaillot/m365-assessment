CREATE TABLE `check_rows` (
	`id` text PRIMARY KEY NOT NULL,
	`run_id` text NOT NULL,
	`section_id` text NOT NULL,
	`category` text NOT NULL,
	`setting` text NOT NULL,
	`current_value` text DEFAULT '' NOT NULL,
	`recommended_value` text DEFAULT '' NOT NULL,
	`status` text NOT NULL,
	`skip_reason` text,
	`check_id` text NOT NULL,
	`remediation` text DEFAULT '' NOT NULL,
	`intent_design` integer DEFAULT false NOT NULL,
	`observed_value` text,
	`expected_value` text,
	`evidence_source` text,
	`evidence_timestamp` text,
	`collection_method` text,
	`permission_required` text,
	`confidence` integer,
	`limitations` text,
	`row_order` integer NOT NULL,
	FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `runs` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`tenant_id` text NOT NULL,
	`status` text DEFAULT 'queued' NOT NULL,
	`started_at` integer NOT NULL,
	`finished_at` integer,
	`error` text,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
