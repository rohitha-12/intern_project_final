# myapp/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import ChatRoom, Message, UserMembership, AdminProfile
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatConsumer1(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'
        self.user = self.scope["user"]

        if not self.user.is_authenticated:
            await self.close()
            return

        self.is_member = await self.check_membership(self.user)

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

        # Send initial status
        await self.send(json.dumps({
            'type': 'connection_established',
            'username': self.user.username,
            'is_member': self.is_member,
            'admin_display_name': await self.get_admin_display_name(self.user)
        }))

        # Send recent messages too
        await self.send_recent_messages()

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

    @database_sync_to_async
    def get_recent_messages(self):
        room = ChatRoom.objects.get(name=self.room_name)
        messages = Message.objects.filter(room=room).order_by('-timestamp')[:50]
        return list(reversed(messages))

    @database_sync_to_async
    def format_poll(self, poll):
        options = []
        for option in poll.options.all():
            user_votes = list(option.pollvote_set.values_list('user__username', flat=True))
            options.append({
                'id': option.id,
                'text': option.text,
                'votes': option.votes,
                'voters': user_votes,
                'user_voted': self.user.username in user_votes
            })

        total_votes = sum(opt['votes'] for opt in options)

        return {
            'id': poll.id,
            'message_id': poll.message.id,
            'question': poll.question,
            'options': options,
            'allow_multiple_answers': poll.allow_multiple_answers,
            'total_votes': total_votes,
            'created_by': poll.message.sender.get_full_name() or poll.message.sender.username,
            'timestamp': poll.message.timestamp.strftime('%I:%M %p')
        }

    @database_sync_to_async
    def format_message(self, message):
        return {
            'id': message.id,
            'sender': message.sender.get_full_name() or message.sender.username,
            'content': message.content,
            'timestamp': message.timestamp.strftime('%I:%M %p'),
            'message_type': message.message_type,
            'is_user': message.sender == self.user,
            'is_pinned': message.is_pinned,
            'reply_to': {
                'id': message.reply_to.id,
                'sender': message.reply_to.sender.get_full_name() or message.reply_to.sender.username,
                'content': message.reply_to.content[:50] + ('...' if len(message.reply_to.content) > 50 else '')
            } if message.reply_to else None
        }

    async def send_recent_messages(self):
        messages = await self.get_recent_messages()
        for message in messages:
            if message.message_type == 'poll':
                poll = await database_sync_to_async(
                    lambda: getattr(message, 'poll', None)
                )()
                if poll:
                    await self.send(text_data=json.dumps({
                        'type': 'poll_message',
                        'poll': await self.format_poll(poll)
                    }))
            else:
                await self.send(text_data=json.dumps({
                    'type': 'chat_message',
                    'message': await self.format_message(message),
                    'is_history': True
                }))

import json
from .models import ChatRoom, Message, Poll, PollOption, PollVote, CustomUser
import asyncio
import random

class ChatConsumer2(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'
        self.user = self.scope["user"]

        if not self.user.is_authenticated:
            await self.close()
            return

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()
        await self.send_recent_messages()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'chat_message':
                await self.handle_chat_message(data)
            elif message_type == 'poll_create':
                await self.handle_poll_create(data)
            elif message_type == 'poll_vote':
                await self.handle_poll_vote(data)
            elif message_type == 'pin_message':
                await self.handle_pin_message(data)
            elif message_type == 'search_messages':
                await self.handle_search_messages(data)

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({'error': 'Invalid JSON'}))

    async def handle_chat_message(self, data):
        content = data['message']
        reply_to_id = data.get('reply_to_id')

        profile = await self.get_user_profile(self.user)
        if not profile.paid:
            return await self.send_message(type='error', message='Premium membership required to send messages')

        if await self.is_abusive(content):
            return await self.send_message(type='error', message='Inappropriate content - not sent.')

        message = await self.save_message(content, 'text', reply_to_id)

        await self.channel_layer.group_send(
            self.room_group_name,
            {'type': 'chat_message', 'message': await self.format_message(message)}
        )

        room = await self.get_or_create_room()
        if room.is_ai_chat:
            await self.send_ai_response(message)

        return


    async def handle_poll_create(self, data):
        profile = await self.get_user_profile(self.user)
        if not profile.paid:
            return await self.send_message(type='error', message='Premium membership required to create polls')

        message = await self.save_message(data['question'], 'poll')
        poll = await self.create_poll(message, data['question'], data.get('allow_multiple_answers', False), data['options'])
        await self.channel_layer.group_send(self.room_group_name, {'type': 'poll_message', 'poll': await self.format_poll(poll)})

    async def handle_poll_vote(self, data):
        result = await self.vote_on_poll(data['option_id'], data['poll_id'])
        if result['success']:
            poll = await self.get_poll(data['poll_id'])
            await self.channel_layer.group_send(self.room_group_name, {'type': 'poll_update', 'poll': await self.format_poll(poll)})
        else:
            await self.send_message(type='error', message=result['error'])

    async def handle_pin_message(self, data):
        if not self.user.is_staff:
            return await self.send_message(type='error', message='Only admins can pin messages')

        message = await self.pin_message(data['message_id'])
        if message:
            await self.channel_layer.group_send(self.room_group_name, {'type': 'message_pinned', 'message': await self.format_message(message)})

    async def handle_search_messages(self, data):
        results = await self.search_messages(data['query'])
        formatted = [await self.format_message(m) for m in results]
        await self.send(text_data=json.dumps({'type': 'search_results', 'messages': formatted}))

    async def send_ai_response(self, user_message):
        await asyncio.sleep(1.5)
        choices = [
            "AI coming soon — available in 45 days.",
            "Learning... full features soon!",
            "Thanks, I'll get smarter by 2025 end.",
            "AI assistant is under development, stay tuned!"
        ]
        ai_resp = random.choice(choices)
        ai_user = await self.get_or_create_ai_user()
        ai_message = await self.save_ai_message(ai_resp, ai_user)
        await self.channel_layer.group_send(self.room_group_name, {'type': 'chat_message', 'message': await self.format_message(ai_message)})

    # group send handlers
    async def chat_message(self, event):
        await self.send(text_data=json.dumps({'type': 'chat_message', 'message': event['message']}))

    async def poll_message(self, event):
        await self.send(text_data=json.dumps({'type': 'poll_message', 'poll': event['poll']}))

    async def poll_update(self, event):
        await self.send(text_data=json.dumps({'type': 'poll_update', 'poll': event['poll']}))

    async def message_pinned(self, event):
        await self.send(text_data=json.dumps({'type': 'message_pinned', 'message': event['message']}))

    # helpers
    async def send_message(self, **kwargs):
        await self.send(text_data=json.dumps(kwargs))

    @database_sync_to_async
    def get_or_create_room(self):
        room, _ = ChatRoom.objects.get_or_create(
            name=self.room_name,
            defaults={'is_ai_chat': 'ai' in self.room_name}
        )
        return room

    @database_sync_to_async
    def get_user_profile(self, user):
        return CustomUser.objects.get_or_create(username=user.username, defaults={'paid': False})[0]

    @database_sync_to_async
    def save_message(self, content, message_type, reply_to_id=None):

        room, _ = ChatRoom.objects.get_or_create(
            name=self.room_name, defaults={'is_ai_chat': 'ai' in self.room_name}
        )

        reply = Message.objects.filter(id=reply_to_id).first() if reply_to_id else None
        message = Message.objects.create(
            room=room,
            sender=self.user,
            content=content,
            message_type=message_type,
            reply_to=reply
        )
        return message
    @database_sync_to_async
    def save_ai_message(self, content, ai_user):
        room, _ = ChatRoom.objects.get_or_create(name=self.room_name, defaults={'is_ai_chat': 'ai' in self.room_name})
        return Message.objects.create(room=room, sender=ai_user, content=content, message_type='text')

    @database_sync_to_async
    def create_poll(self, message, question, allow_multiple, options):
        poll = Poll.objects.create(message=message, question=question, allow_multiple_answers=allow_multiple)
        for opt in options:
            PollOption.objects.create(poll=poll, text=opt['text'])
        return poll

    @database_sync_to_async
    def vote_on_poll(self, opt_id, poll_id):
        try:
            option = PollOption.objects.get(id=opt_id, poll_id=poll_id)
        except PollOption.DoesNotExist:
            return {'success': False, 'error': 'Option not found'}
        existing = PollVote.objects.filter(poll_option__poll=option.poll, user=self.user)
        if not option.poll.allow_multiple_answers and existing.exists():
            existing.delete()
        vote, created = PollVote.objects.get_or_create(poll_option=option, user=self.user)
        if not created: vote.delete()
        option.votes = option.pollvote_set.count()
        option.save()
        return {'success': True}

    @database_sync_to_async
    def get_poll(self, poll_id):
        return Poll.objects.get(id=poll_id)

    @database_sync_to_async
    def pin_message(self, message_id):
        msg = Message.objects.filter(id=message_id).first()
        if msg:
            msg.is_pinned, msg.pinned_by = True, self.user
            msg.save()
        return msg

    @database_sync_to_async
    def search_messages(self, query):
        room, _ = ChatRoom.objects.get_or_create(name=self.room_name, defaults={'is_ai_chat': False})
        return list(Message.objects.filter(room=room, content__icontains=query).order_by('-timestamp')[:20])

    @database_sync_to_async
    def get_recent_messages(self):
        room, _ = ChatRoom.objects.get_or_create(name=self.room_name, defaults={'is_ai_chat': False})
        return list(Message.objects.filter(room=room).order_by('-timestamp')[:50])

    @database_sync_to_async
    def format_message(self, msg):
        return {
            'id': msg.id,
            'sender': msg.sender.username if msg.sender.username else msg.sender.full_name,
            'content': msg.content,
            'timestamp': msg.timestamp.strftime('%I:%M %p'),
            'is_pinned': msg.is_pinned,
            'reply_to': {
                'id': msg.reply_to.id,
                'sender': msg.reply_to.sender.get_full_name() or msg.reply_to.sender.username,
                'content': msg.reply_to.content[:50] + ('...' if len(msg.reply_to.content)>50 else '')
            } if msg.reply_to else None
        }

    @database_sync_to_async
    def format_poll(self, poll):
        opts = []
        for o in poll.options.all():
            voters = list(o.pollvote_set.values_list('user__username', flat=True))
            opts.append({'id': o.id, 'text': o.text, 'votes': o.votes, 'voters': voters, 'user_voted': self.user.username in voters})
        return {'id': poll.id, 'message_id': poll.message.id, 'question': poll.question, 'options': opts, 'allow_multiple_answers': poll.allow_multiple_answers, 'total_votes': sum(o['votes'] for o in opts), 'created_by': poll.message.sender.get_full_name() or poll.message.sender.username}

    @database_sync_to_async
    def is_abusive(self, content):
        forbidden = ['spam','hate','abuse']
        low = content.lower()
        return any(w in low for w in forbidden)

    @database_sync_to_async
    def get_or_create_ai_user(self):
        return User.objects.get_or_create(username='AI_Assistant', defaults={'first_name':'AI','last_name':'Assistant','email':'ai@assistant.com'})[0]

    async def send_recent_messages(self):
        msgs = await self.get_recent_messages()
        for m in msgs:
            await self.send(text_data=json.dumps({'type':'chat_message', 'message': await self.format_message(m), 'is_history': True}))
