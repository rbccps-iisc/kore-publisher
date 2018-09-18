#include "kore-publisher.h"

ht *hash_table = NULL;

typedef struct myconnection {
	amqp_connection_state_t		*amqp_connection;
	pthread_mutex_t			mutex;	
}connection_t; 

int
ep_index(struct http_request *req)
{
	http_response(req, 200, "index-page",10 );
	return (KORE_RESULT_OK);
}

int
init (int state)
{
	if (worker->id > 0 && hash_table == NULL)
	{
		if (! (hash_table = (ht *) malloc(sizeof(ht))) )
			exit (-1);

		ht_init (hash_table);
	}

	return KORE_RESULT_OK;
}

int
ep_publish (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *exchange;
	const char *topic;
	const char *message;

	// amqp_basic_properties_t props;

	char id_apikey[128];

	amqp_socket_t 		*socket;
	connection_t 		*connection;

	node 		*c = NULL;

	dprintf("PUBLISH\n");

	amqp_rpc_reply_t 	login_reply;
	amqp_rpc_reply_t 	rpc_reply;

	dprintf("-----\n");
	dprintf("%d\n",http_request_header(req, "id", &id)); 
	dprintf("%d\n",http_request_header(req, "apikey", &apikey)); 
	dprintf("%d\n",http_request_header(req, "to", &exchange)); 
	dprintf("%d\n",http_request_header(req, "topic", &topic)); 
	dprintf("%d\n",http_request_header(req, "message", &message)); 

	if (KORE_RESULT_OK != http_request_header(req, "id", &id) 
				||
	    KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
	    KORE_RESULT_OK != http_request_header(req, "to", &exchange)
				||
	    KORE_RESULT_OK != http_request_header(req, "topic", &topic)
	)
	{
		bad_request();
	}

	if (http_request_header(req, "message", &message) != KORE_RESULT_OK)
	{
		if (!(message = req->http_body->data))	
			bad_request();
	}

	strlcpy(id_apikey,id,40);
	strlcat(id_apikey,":",1);
	strlcat(id_apikey,apikey,40);

	dprintf("Reached here %s : %p\n",id,hash_table);

	if ((c = ht_search(hash_table,id_apikey)))
	{
		dprintf("---, got 1\n");
		connection = c->value;
	}
	else
	{
		dprintf("---, got 2\n");
		connection = malloc(sizeof(connection_t));
		if (connection == NULL)
		{
			internal_error();
		}

		connection->amqp_connection = malloc(sizeof(amqp_connection_state_t));
		if (connection->amqp_connection == NULL)
		{
			internal_error();
		}

		if (pthread_mutex_init(&connection->mutex,0) != 0)
		{
			internal_error();
		}

reconnect:
		*(connection->amqp_connection) = amqp_new_connection();
		socket 	= amqp_tcp_socket_new(*(connection->amqp_connection));

		if (socket == NULL)
		{
			dprintf("Got socket null\n");
			internal_error();
		}

		if (amqp_socket_open(socket, "127.0.0.1", 5672)) {
			dprintf("open failed \n");
			internal_error();
		}

		login_reply = amqp_login(*(connection->amqp_connection), "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, id, apikey);
		dprintf("Got %d\n",login_reply.reply_type);
		if (login_reply.reply_type != AMQP_RESPONSE_NORMAL) {
			forbidden();
		}

		dprintf("Got login reply\n");

		if (! amqp_channel_open(*(connection->amqp_connection), 1)) {
			forbidden();
		}

		dprintf("Channel oopen\n");

		rpc_reply = amqp_get_rpc_reply(*(connection->amqp_connection));
		if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL) {
			forbidden();
		}

		dprintf("Got reply !\n");

		ht_insert (hash_table, id_apikey, connection);
	}

	//props.user_id = amqp_cstring_bytes(id);

	pthread_mutex_lock(&connection->mutex);
	if (AMQP_STATUS_OK != amqp_basic_publish (	
				*(connection->amqp_connection),
				1,
				amqp_cstring_bytes(exchange),
               	 		amqp_cstring_bytes(topic),
				0,
				0,
				NULL,
               			amqp_cstring_bytes(message))
	)
	{
		pthread_mutex_unlock(&connection->mutex);
		forbidden();
	}
	pthread_mutex_unlock(&connection->mutex);

	dprintf("Published to %s : %s : %s\n\n",exchange,topic,message);

	ok202();
}
