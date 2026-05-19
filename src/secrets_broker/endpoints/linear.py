"""Linear (project management) — GraphQL through a shared client.

Requires secret: linear-api-key. Linear uses a bare token (no Bearer prefix).
"""
from __future__ import annotations

import json
import urllib.request

from ..secrets import get_secret


def _linear_call(query: str, variables: dict | None = None) -> dict:
    api_key = get_secret("linear-api-key")
    payload = {"query": query, "variables": variables or {}}
    req = urllib.request.Request(
        "https://api.linear.app/graphql",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": api_key,  # Linear uses bare token, no "Bearer " prefix
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        result = json.loads(resp.read())
    if "errors" in result:
        raise RuntimeError(f"Linear GraphQL error: {result['errors']}")
    return result.get("data", {})


def handle_linear_issues_list(body: dict) -> tuple[int, dict]:
    """List issues. Body: {teamId?, projectId?, stateType?, limit?}.
    stateType: backlog | unstarted | started | completed | canceled."""
    filter_clauses = []
    if "teamId" in body:
        filter_clauses.append(f'team: {{id: {{eq: "{body["teamId"]}"}}}}')
    if "projectId" in body:
        filter_clauses.append(f'project: {{id: {{eq: "{body["projectId"]}"}}}}')
    if "stateType" in body:
        filter_clauses.append(f'state: {{type: {{eq: "{body["stateType"]}"}}}}')
    filter_str = "filter: {" + ", ".join(filter_clauses) + "}, " if filter_clauses else ""
    limit = int(body.get("limit", 50))
    query = f"""query {{
      issues({filter_str}first: {limit}) {{
        nodes {{
          id identifier title description priority createdAt updatedAt
          state {{ name type }}
          assignee {{ name email }}
          team {{ name key }}
          project {{ name id }}
        }}
      }}
    }}"""
    data = _linear_call(query)
    return 200, {"issues": data.get("issues", {}).get("nodes", [])}


def handle_linear_issue_create(body: dict) -> tuple[int, dict]:
    """Create an issue. Body: {teamId, title, description?, projectId?, assigneeId?, priority?, stateId?}.
    teamId is required. Get it from /linear/teams/list."""
    if "teamId" not in body or "title" not in body:
        raise KeyError("teamId and title are required")
    input_fields = {"teamId": body["teamId"], "title": body["title"]}
    for k in ("description", "projectId", "assigneeId", "priority", "stateId"):
        if k in body:
            input_fields[k] = body[k]
    query = """mutation IssueCreate($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue { id identifier title url state { name } }
      }
    }"""
    data = _linear_call(query, {"input": input_fields})
    return 200, data.get("issueCreate", {})


def handle_linear_issue_update(body: dict) -> tuple[int, dict]:
    """Update an issue. Body: {id, title?, description?, stateId?, assigneeId?, priority?, projectId?}."""
    if "id" not in body:
        raise KeyError("id is required")
    issue_id = body["id"]
    input_fields = {
        k: v for k, v in body.items()
        if k != "id" and k in ("title", "description", "stateId", "assigneeId", "priority", "projectId")
    }
    if not input_fields:
        raise KeyError("at least one field to update is required")
    query = """mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
      issueUpdate(id: $id, input: $input) {
        success
        issue { id identifier title state { name } }
      }
    }"""
    data = _linear_call(query, {"id": issue_id, "input": input_fields})
    return 200, data.get("issueUpdate", {})


def handle_linear_issue_comment(body: dict) -> tuple[int, dict]:
    """Add a comment to an issue. Body: {issueId, body}."""
    if "issueId" not in body or "body" not in body:
        raise KeyError("issueId and body are required")
    query = """mutation CommentCreate($input: CommentCreateInput!) {
      commentCreate(input: $input) {
        success
        comment { id body url }
      }
    }"""
    data = _linear_call(query, {"input": {"issueId": body["issueId"], "body": body["body"]}})
    return 200, data.get("commentCreate", {})


def handle_linear_teams_list(_body: dict) -> tuple[int, dict]:
    """List all teams in the workspace."""
    query = """{
      teams(first: 50) {
        nodes { id name key description }
      }
    }"""
    data = _linear_call(query)
    return 200, {"teams": data.get("teams", {}).get("nodes", [])}


def handle_linear_projects_list(body: dict) -> tuple[int, dict]:
    """List projects, optionally filtered by team. Body: {teamId?, limit?}."""
    filter_str = (
        f'filter: {{accessibleTeams: {{some: {{id: {{eq: "{body["teamId"]}"}}}}}}}}, '
        if "teamId" in body else ""
    )
    limit = int(body.get("limit", 50))
    query = f"""{{
      projects({filter_str}first: {limit}) {{
        nodes {{ id name description state url progress targetDate }}
      }}
    }}"""
    data = _linear_call(query)
    return 200, {"projects": data.get("projects", {}).get("nodes", [])}


def handle_linear_project_create(body: dict) -> tuple[int, dict]:
    """Create a project. Body: {name, teamIds: [<teamId>], description?, content?, leadId?, state?, targetDate?, startDate?}.
    state values: backlog | planned | started | paused | completed | canceled."""
    if "name" not in body or "teamIds" not in body:
        raise KeyError("name and teamIds (array) are required")
    input_fields = {"name": body["name"], "teamIds": body["teamIds"]}
    for k in ("description", "content", "leadId", "memberIds", "state", "targetDate", "startDate", "color", "icon"):
        if k in body:
            input_fields[k] = body[k]
    query = """mutation ProjectCreate($input: ProjectCreateInput!) {
      projectCreate(input: $input) {
        success
        project { id name description state url targetDate startDate }
      }
    }"""
    data = _linear_call(query, {"input": input_fields})
    return 200, data.get("projectCreate", {})


def handle_linear_project_update(body: dict) -> tuple[int, dict]:
    """Update a project. Body: {id, name?, description?, content?, state?, leadId?, targetDate?, startDate?}."""
    if "id" not in body:
        raise KeyError("id is required")
    proj_id = body["id"]
    input_fields = {
        k: v for k, v in body.items()
        if k != "id" and k in ("name", "description", "content", "state", "leadId",
                               "targetDate", "startDate", "memberIds", "color", "icon")
    }
    if not input_fields:
        raise KeyError("at least one field to update is required")
    query = """mutation ProjectUpdate($id: String!, $input: ProjectUpdateInput!) {
      projectUpdate(id: $id, input: $input) {
        success
        project { id name state url }
      }
    }"""
    data = _linear_call(query, {"id": proj_id, "input": input_fields})
    return 200, data.get("projectUpdate", {})


def handle_linear_workflow_states(body: dict) -> tuple[int, dict]:
    """List workflow states for a team. Body: {teamId}.
    Use to get stateId for issue create/update."""
    if "teamId" not in body:
        raise KeyError("teamId is required")
    query = f"""{{
      workflowStates(filter: {{team: {{id: {{eq: "{body["teamId"]}"}}}}}}) {{
        nodes {{ id name type position }}
      }}
    }}"""
    data = _linear_call(query)
    return 200, {"states": data.get("workflowStates", {}).get("nodes", [])}


ENDPOINTS = {
    "/linear/issues/list": handle_linear_issues_list,
    "/linear/issue/create": handle_linear_issue_create,
    "/linear/issue/update": handle_linear_issue_update,
    "/linear/issue/comment": handle_linear_issue_comment,
    "/linear/teams/list": handle_linear_teams_list,
    "/linear/projects/list": handle_linear_projects_list,
    "/linear/project/create": handle_linear_project_create,
    "/linear/project/update": handle_linear_project_update,
    "/linear/workflow-states": handle_linear_workflow_states,
}
