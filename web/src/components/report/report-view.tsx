import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import type { ReportData } from "@/report/build-report-data";
import { OverviewTab } from "./overview-tab";
import { FindingsTab } from "./findings-tab";
import { RemediationTab } from "./remediation-tab";
import { ReviewsTab } from "./reviews-tab";
import { FrameworksTab } from "./frameworks-tab";

export function ReportView({ data }: { data: ReportData }) {
  const reviewCount = data.summary.review;
  return (
    <Tabs defaultValue="overview" className="w-full">
      <TabsList variant="line" className="w-full justify-start">
        <TabsTrigger value="overview" className="data-[state=active]:text-primary data-[state=active]:after:bg-primary">
          Overview
        </TabsTrigger>
        <TabsTrigger value="findings" className="data-[state=active]:text-primary data-[state=active]:after:bg-primary">
          Findings
        </TabsTrigger>
        <TabsTrigger value="remediation" className="data-[state=active]:text-primary data-[state=active]:after:bg-primary">
          Remediation
        </TabsTrigger>
        <TabsTrigger
          value="reviews"
          className={`data-[state=active]:text-primary data-[state=active]:after:bg-primary ${reviewCount > 0 ? "data-[state=active]:after:bg-review text-review" : ""} ${reviewCount > 0 ? "bg-review/15 border border-review/30 rounded-md" : ""}`}
        >
          <span className="flex items-center gap-1.5">
            Reviews
            <Badge
              variant={reviewCount > 0 ? "outline" : "secondary"}
              className={reviewCount > 0 ? "bg-review text-white border-review/30 px-1.5 py-0 text-xs" : "px-1.5 py-0 text-xs"}
            >
              {reviewCount}
            </Badge>
          </span>
        </TabsTrigger>
        <TabsTrigger value="frameworks" className="data-[state=active]:text-primary data-[state=active]:after:bg-primary">
          Frameworks
        </TabsTrigger>
      </TabsList>

      <TabsContent value="overview" className="pt-md">
        <OverviewTab data={data} />
      </TabsContent>
      <TabsContent value="findings" className="pt-md">
        <FindingsTab data={data} />
      </TabsContent>
      <TabsContent value="remediation" className="pt-md">
        <RemediationTab data={data} />
      </TabsContent>
      <TabsContent value="reviews" className="pt-md">
        <ReviewsTab data={data} />
      </TabsContent>
      <TabsContent value="frameworks" className="pt-md">
        <FrameworksTab data={data} />
      </TabsContent>
    </Tabs>
  );
}
