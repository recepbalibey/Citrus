import pandas as pd
import datetime
import numpy as np
import matplotlib.pyplot as plt
from statsmodels.tsa.api import VAR, VARMAX
from .helper import Helper
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima_model import ARMA, ARIMA, ARMAResults, ARIMAResults
from statsmodels.tools.eval_measures import rmse
from pmdarima import auto_arima
import functools
from fbprophet import Prophet
#import sys
#sys.path.insert(0, '/../tangerine/providers')
#from providers.cve import CVE
import os
import logging

class Models():

    def __init__(self):
       # self._cve = CVE()
       # cve_2020 = self._cve.parse('2020')
       # cve_all = cve_2020.union(self._cve.parse('2019'))
       # self.cve_ts = self._cve.get_ts(cve_all)
       # logging.getLogger('fbprophet').setLevel(logging.WARNING)
       # pd.plotting.register_matplotlib_converters()
        pass
        #print(self.cve_ts)
    
    def apply(self, name, df, host):
        model = getattr(Models, name)
        return model(self, df, host)

    #MAKE MULTITHREADED???
    def mprophet(self, df, host):

        if df is None:
            print("DF Does not exist for host???")
            return
        

        # TODO:
        # Look @ models which requires less data points
        if len(df) < 10:
            print("DF Length < 10")
            print("Possibly use other model?")
            print(df)
            return

        dic = {}
        
        print(df)
        
        # ------------------------------------------------------------------------------ #
        # TODO: Use feed w/ most data points, with others supporting as extra regressors #
        # Should do it when patching TS - check TS with  most non zero values            # 
        # Will then also need to make good/bad extra models to compare with new model    #
        # ------------------------------------------------------------------------------ #

        df.reset_index(level=0, inplace=True)
        df = df.rename({'Date': 'ds'}, axis=1)

        df = df.rename({"abuseipdb": 'y'}, axis=1)
        
        df['cap'] = 100
        df['floor'] = 0

        test_len = int(len(df) / 10) + 1
        train_len = len(df) - test_len
        #train_len = len(df)

        train = df.iloc[:train_len]

        test = df.iloc[train_len:]

        #print("----- TRAIN DF ----")
        #print(train)
        #print("------ TEST DF-----")
        #print(test)
        #print(df)
        
        startDate = df['ds'].iloc[0]
        endDate = df['ds'].iloc[-1]

        #print(startDate)
        #print(endDate)
        #print(self.cve_ts)

        cve_days = self.cve_ts[startDate:endDate]
        cve_days.reset_index(level=0, inplace=True)
        cve_days = cve_days.rename({'Date': 'ds'}, axis=1)
        cve_days = cve_days.rename({0: 'holiday'}, axis=1)
        #print(cve_days)
        m = Prophet(holidays=cve_days, growth='logistic')
 
        cols = ['otx', 'apility']
        for col in cols:
            if col in df.columns:
                m.add_regressor(col, prior_scale=0.5, mode='multiplicative')
        
        #Need to fit to length of TS
        #if host.asn_changes is not None:
           #m.add_regressor('asn', prior_scale=0.5, mode='multiplicative')

        try:

            with suppress_stdout_stderr():
                m.fit(train)

        except Exception as e:

            print(f"Exception raised in training - likely that data set has multiple zeros's")
            print(e)
            return

        future = m.make_future_dataframe(periods=test_len)
        
        future['cap'] = 60
        future['floor'] = 0
        for col in cols:
            if col in df.columns:
                future[col] = df[col][:train_len]
        
        #future['otx'] = df['otx'][:train_len]

        future = future.replace(np.nan, 0)

        #print(future.head())

        forecast = m.predict(future)

        preds = forecast.iloc[-test_len:]['yhat']
        #print(preds)
        print(f"{host.ip} \n {df}")
        print(f"Predictions : {preds}")
        #print(test['y'].head())
        #print(test.head())

        #print("-- RMSE --")
        #print(rmse(preds, test['y']))
        #print("-- Mean --")
        #print(test['y'].mean())




        #ax = forecast.plot(x='ds', y='yhat', label='Predictions', legend=True, title=host.ip)
        #train.plot(x='ds', y='y', label='train data', legend=True, ax=ax, title=host.ip)
        #test.plot(x='ds', y='y', label='test data', legend=True, ax=ax, title=host.ip)

        #for day in cve_days['ds']:
        #   ax.axvline(x=day, color='black', alpha=0.8)
        #plt.show()

        #m.plot_components(forecast)
        #plt.show()

        num_bins = 30
        counts, bin_edges = np.histogram (forecast['yhat'], bins=num_bins, normed=True)
        cdf = np.cumsum (counts)
        dic[host.ip + "_" + "mprophet"] = {'cdf': cdf, 'bin_edges': bin_edges, 'values': forecast['yhat'], 'train': train['y'], 'test': test['y'], 'modelType': 'mprophet', 'feedType': 'abuseipdb', 'forecast':forecast, "_train": train, "_test": test}
        return dic

    def prophet(self, df, host):
        
        pd.plotting.register_matplotlib_converters()
        dic = {} 
        for _ts in df:
            ts = _ts.get()

            if len(ts) < 5:
                continue 

            if isinstance(ts, pd.Series):
                ts = pd.DataFrame(ts, columns=[_ts.getType()])

            ts = ts.rename({_ts.getType(): 'y'}, axis=1)
            ts.reset_index(level=0, inplace=True)
            ts = ts.rename({'Date': 'ds'}, axis=1)
            print(ts)

            test_len = int(len(ts) / 20)
            train_len = len(ts) - test_len

            train = ts.iloc[:train_len]
            test = ts.iloc[train_len:]

            startDate = ts['ds'].iloc[0]
            endDate = ts['ds'].iloc[-1]
            print(startDate)
            print(endDate)
            print(self.cve_ts)
            cve_days = self.cve_ts[startDate:endDate]
            cve_days.reset_index(level=0, inplace=True)
            cve_days = cve_days.rename({'Date': 'ds'}, axis=1)
            cve_days = cve_days.rename({0: 'holiday'}, axis=1)
            print(cve_days)

            ts['floor'] = 0
            m = Prophet(holidays=cve_days)
            m.fit(train)

            future = m.make_future_dataframe(periods=test_len)
            future['floor'] = 0
            forecast = m.predict(future)

            print(forecast.tail())

            preds = forecast.iloc[-test_len:]['yhat']
            print(preds)
            print("-- RMSE --")
            print(rmse(preds, test['y']))
            print("-- Mean --")
            print(test['y'].mean())
            print(forecast)

            num_bins = 30
            
            counts, bin_edges = np.histogram (forecast['yhat'], bins=num_bins, normed=True)
            cdf = np.cumsum (counts)

            dic[host.ip + "_" + _ts.getType()] = {'cdf': cdf, 'bin_edges': bin_edges, 'values': forecast['yhat'], 'modelType': 'prophet', 'feedType': _ts.getType(), 'forecast': forecast}
            
            ax = forecast.plot(x='ds', y='yhat', label='Predictions', legend=True, title=_ts.getType() + " " + host.ip)
            train.plot(x='ds', y='y', label='train data', legend=True, ax=ax, title=_ts.getType() + " " + host.ip)
            test.plot(x='ds', y='y', label='test data', legend=True, ax=ax, title=_ts.getType() + " " + host.ip)
            #for day in cve_days['ds']:
            #    ax.axvline(x=day, color='black', alpha=0.8)
            plt.show()
        
        #for _, v in dic.items():
            #print(v)
            #plt.plot (v['bin_edges'][1:], v['cdf']/v['cdf'][-1])
            #m.plot_components(forecast)
        #plt.show()
        #print(dic)

        return dic

    def var(self, df, host):

        df_diffed, no_diffs = Helper.diff_test(df)

        print(df_diffed)
        df_diffed.replace([np.inf, -np.inf], np.nan)
        cols = df_diffed.columns
        df_diffed = df_diffed.dropna()

        print("Length  : " + str(len(df_diffed)))
        nobs = int(len(df_diffed) / 10) + 2
        train = df_diffed[:-nobs]
        test = df_diffed[-nobs:]
        #print(train)
        model = VAR(train)

        maxlags = int(nobs / 2) + 1

        aic = model.select_order(maxlags).selected_orders['aic']

        results = model.fit(aic)
        print(results.summary())

        lagged_values = train.values[-maxlags:]
        #print(lagged_values)
        forecast = results.forecast(y=lagged_values, steps=nobs)

        idx = pd.date_range(test.first_valid_index(), periods=nobs)
 
        df_forecast = pd.DataFrame(data=forecast, index = idx, columns=cols)
        #print(df_forecast)

        df_fixed = Helper.reverse_diff(df_forecast, df, nobs, no_diffs)

        


        test_range = df[-nobs:]
        print("-- TEST Result -- \n")
        print(test_range)
        print("-- TEST Result END -- \n")
        print("-- Forecast Result -- \n")
        print(df_fixed)
        print("-- Forecast Result END -- \n")

        for col in df.columns:
            print("-- RMSE --")
            print(rmse(test_range[col], df_fixed[col + '_forecast']))
            print("-- Mean --")
            print(test_range[col].mean())
            df[col].plot(legend=True)
            df_fixed[col + '_forecast'].plot(legend=True)
            plt.show()

    def varma(self, df, host):

        pd.plotting.register_matplotlib_converters()
        df_diffed, no_diffs = Helper.diff_test(df)

        print(df_diffed)
        df_diffed.replace([np.inf, -np.inf], np.nan)
        cols = df_diffed.columns
        df_diffed = df_diffed.dropna()
        nobs = int(len(df_diffed) / 10) + 2
        train = df_diffed[:-nobs]
        test = df_diffed[-nobs:]
        
        model = VARMAX(train, order=(2,2), trend='c')
        results = model.fit(maxiter=1000, disp=False)
        print(results.summary())

        df_forecast = results.forecast(nobs)

        print(df_forecast)
        df_fixed = Helper.reverse_diff(df_forecast, df, nobs, no_diffs)
        print(df_fixed)

        for col in df.columns:
            print("-- RMSE --")
            print(rmse(test[col], df_fixed[col + '_forecast']))
            print("-- Mean --")
            print(test[col].mean())
            df[col].plot(legend=True)
            df_fixed[col + '_forecast'].plot(legend=True)
            plt.show()

    def arima(self, TS, host):

        pd.plotting.register_matplotlib_converters()

        for _ts in TS:

            
            ts = _ts.get()


            #DATAFRAME NOT LARGE ENOUGH
            if len(ts) < 10:
                continue
            
            #train_len = int((len(_ts) * (80/100)))
            df_diffed, no_diffs = Helper.diff_test(ts)
            
            nobs = int(len(ts) / 10) + 2
            train = ts[:-nobs]
            test = ts[-nobs:]

            #train_len = len(ts) - 5
            #train = ts.iloc[:train_len]
            #test = ts.iloc[train_len:]
            print(train)
            ar = ARIMA(train, order=(3, no_diffs, 3))
            results = ar.fit()
            #results.summary()
            start = len(train)
            end = len(train) + len(test) - 1
            predictions = results.predict(start,end).rename("ARIMA Preds")
            ax = train.plot(legend=True, label='training', title=_ts.getType() + host.ip)
            test.plot(legend=True, label='testing', title=_ts.getType() + host.ip, ax=ax)

            predictions.plot(legend=True, title=_ts.getType() + " - " + host.ip, ax=ax)
            plt.show()
    
    def arma(self, TS, host):


        pd.plotting.register_matplotlib_converters()

        for _ts in TS:

            ts = _ts.get()
            if len(ts) < 10:

                continue


            if isinstance(ts, pd.Series):
                ts = pd.DataFrame(ts, columns=[_ts.getType()])
            #else:
            #    ts = ts.rename({0: _ts.getType()}, axis=1)

            print(ts)
            df_diffed, no_diffs = Helper.diff_test(ts)
            print(df_diffed)

            nobs = int(len(df_diffed) / 10) + 2
            train = df_diffed[:-nobs]
            test = df_diffed[-nobs:]

            #try:
            #    pq = auto_arima(ts, maxiter=1000, d=0)
            #    print(pq)

            #except ValueError:
            #    print("AUTO Arima failed, likely non-stationary?")

            model = ARMA(train, order=(1,2))
            results = model.fit(disp=False)

            #print(results.summary())

            start = len(train)
            end = len(train) + len(test)-1

            z1 = results.predict(start=start, end=end).rename(_ts.getType())
            z1 = z1.to_frame()
            z1.columns = [_ts.getType()]

            
            #NEED TO FIX REVERSE DIFF FOR SERIES (Not DF)
            df_fixed = Helper.reverse_diff(z1, ts, nobs, no_diffs)

            print(z1)

            print("-- RMSE --")
            print(rmse(test, df_fixed[_ts.getType()]))
            print("-- Mean --")
            print(test.mean())
            ax = ts.plot(legend=True)

            df_fixed[_ts.getType() + "_forecast"].plot(ax=ax, legend=True)
            #ts.plot(legend=True)
            #z1.plot(legend=True)
            plt.show()

class suppress_stdout_stderr(object):
    '''
    A context manager for doing a "deep suppression" of stdout and stderr in
    Python, i.e. will suppress all print, even if the print originates in a
    compiled C/Fortran sub-function.
       This will not suppress raised exceptions, since exceptions are printed
    to stderr just before a script exits, and after the context manager has
    exited (at least, I think that is why it lets exceptions through).

    '''
    def __init__(self):
        # Open a pair of null files
        self.null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
        # Save the actual stdout (1) and stderr (2) file descriptors.
        self.save_fds = [os.dup(1), os.dup(2)]

    def __enter__(self):
        # Assign the null pointers to stdout and stderr.
        os.dup2(self.null_fds[0], 1)
        os.dup2(self.null_fds[1], 2)

    def __exit__(self, *_):
        # Re-assign the real stdout/stderr back to (1) and (2)
        os.dup2(self.save_fds[0], 1)
        os.dup2(self.save_fds[1], 2)
        # Close the null files
        for fd in self.null_fds + self.save_fds:
            os.close(fd)