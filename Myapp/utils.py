from django.conf import settings
import requests

def fetch_public_vimeo_video(video_id):
    """Fetches a public Vimeo video by ID."""
    try:
        url = f"https://vimeo.com/api/v2/video/{video_id}.json"
        response = requests.get(url)
        response.raise_for_status()
        video_data = response.json()
        return {
            "video_id": video_id,
            "video_url": video_data[0]["url"]
        }
    except requests.RequestException as e:
        return {"error": str(e)}

def fetch_unlisted_vimeo_video(video_id):
    """Fetches an unlisted Vimeo video using an access token."""
    try:
        url = f"https://api.vimeo.com/videos/{video_id}"
        headers = {
            "Authorization": f"Bearer {settings.VIMEO_ACCESS_TOKEN}"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        video_data = response.json()
        return {
            "video_id": video_id,
            "video_url": video_data.get("link")
        }
    except requests.RequestException as e:
        return {"error": str(e)}
