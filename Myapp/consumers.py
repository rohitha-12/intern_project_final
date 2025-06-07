# myapp/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import ChatRoom, Message, UserMembership, AdminProfile
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'

        self.user = self.scope['user']
        if not self.user.is_authenticated:
            await self.close()
            return

        # Check membership status from DB
        self.is_member = await self.check_membership(self.user)

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

        # Send initial status to client
        await self.send(json.dumps({
            'type': 'connection_established',
            'username': self.user.username,
            'is_member': self.is_member,
            'admin_display_name': await self.get_admin_display_name(self.user)
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')

        # Only members can send messages or perform chat actions
        if not self.is_member:
            await self.send(json.dumps({'error': 'Membership required to send messages.'}))
            return

        if action == 'send_message':
            content = data.get('content')
            if content:
                message = await self.create_message(self.user, self.room_name, content)
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message_id': message.id,
                        'username': self.user.username,
                        'content': content,
                        'timestamp': message.timestamp.isoformat(),
                        'is_pinned': message.is_pinned,
                    }
                )
        elif action == 'pin_message':
            # Admin only
            if await self.is_admin(self.user):
                message_id = data.get('message_id')
                if message_id:
                    await self.pin_unpin_message(message_id, True)
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            'type': 'message_pinned',
                            'message_id': message_id,
                            'pinned_by': self.user.username
                        }
                    )
            else:
                await self.send(json.dumps({'error': 'Only admins can pin messages.'}))
        elif action == 'unpin_message':
            # Admin only
            if await self.is_admin(self.user):
                message_id = data.get('message_id')
                if message_id:
                    await self.pin_unpin_message(message_id, False)
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            'type': 'message_unpinned',
                            'message_id': message_id,
                            'unpinned_by': self.user.username
                        }
                    )
            else:
                await self.send(json.dumps({'error': 'Only admins can unpin messages.'}))
        elif action == 'delete_message':
            # Admin can delete any, user can delete own message (later)
            message_id = data.get('message_id')
            if message_id:
                can_delete = False
                if await self.is_admin(self.user):
                    can_delete = True
                else:
                    # Later: implement user own message deletion permission
                    can_delete = False

                if can_delete:
                    await self.delete_message(message_id)
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            'type': 'message_deleted',
                            'message_id': message_id,
                            'deleted_by': self.user.username
                        }
                    )
                else:
                    await self.send(json.dumps({'error': 'Permission denied to delete message.'}))
        elif action == 'poll_create':
            # Admin only - placeholder for poll creation
            if await self.is_admin(self.user):
                # Implement poll creation logic here in future
                await self.send(json.dumps({'info': 'Poll feature coming soon.'}))
            else:
                await self.send(json.dumps({'error': 'Only admins can create polls.'}))

    # Handlers for group_send events:

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message_id': event['message_id'],
            'username': event['username'],
            'content': event['content'],
            'timestamp': event['timestamp'],
            'is_pinned': event['is_pinned'],
        }))

    async def message_pinned(self, event):
        await self.send(text_data=json.dumps({
            'type': 'message_pinned',
            'message_id': event['message_id'],
            'pinned_by': event['pinned_by']
        }))

    async def message_unpinned(self, event):
        await self.send(text_data=json.dumps({
            'type': 'message_unpinned',
            'message_id': event['message_id'],
            'unpinned_by': event['unpinned_by']
        }))

    async def message_deleted(self, event):
        await self.send(text_data=json.dumps({
            'type': 'message_deleted',
            'message_id': event['message_id'],
            'deleted_by': event['deleted_by']
        }))

    # Database helper methods

    @database_sync_to_async
    def check_membership(self, user):
        try:
            membership = UserMembership.objects.get(user=user)
            return membership.is_member
        except UserMembership.DoesNotExist:
            return False

    @database_sync_to_async
    def create_message(self, user, room_name, content):
        room, _ = ChatRoom.objects.get_or_create(name=room_name)
        message = Message.objects.create(user=user, room=room, content=content)
        return message

    @database_sync_to_async
    def is_admin(self, user):
        # You can improve this based on your admin model/permissions
        return user.is_staff or AdminProfile.objects.filter(user=user).exists()

    @database_sync_to_async
    def pin_unpin_message(self, message_id, pin=True):
        try:
            message = Message.objects.get(id=message_id)
            message.is_pinned = pin
            message.save()
            return True
        except Message.DoesNotExist:
            return False

    @database_sync_to_async
    def delete_message(self, message_id):
        try:
            message = Message.objects.get(id=message_id)
            message.delete()
            return True
        except Message.DoesNotExist:
            return False

    @database_sync_to_async
    def get_admin_display_name(self, user):
        try:
            admin_profile = AdminProfile.objects.get(user=user)
            return admin_profile.display_name
        except AdminProfile.DoesNotExist:
            return None