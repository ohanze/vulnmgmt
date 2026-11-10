from django.contrib import admin

from dojo.ssvc.models import SSVCDecision


@admin.register(SSVCDecision)
class SSVCDecisionAdmin(admin.ModelAdmin):

    """Read-only w adminie: SSVCDecision jest niemutowalnym rekordem historii (model.save()/delete() to wymuszają)."""

    list_display = ("id", "finding", "outcome", "criticality", "tree_id", "tree_version", "needs_review", "created")
    list_filter = ("outcome", "criticality", "needs_review", "tree_id", "tree_version")
    readonly_fields = [f.name for f in SSVCDecision._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
