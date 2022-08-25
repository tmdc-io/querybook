import { createBrowserHistory } from 'history';

const history = createBrowserHistory({
    /* pass a configuration object here if needed */
    basename: '/querybook',
});

export default history;
